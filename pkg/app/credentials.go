// Service accounts: the client_credentials grant for machines with no browser
// and no human. The profile names where the secret lives; it is read at every
// mint, so rotating it needs no restart.

package app

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/vmkteam/mcpurl/pkg/oauth"
)

// validateGrant checks the grant settings of a resolved profile. Exactly one
// credential shape, each from exactly one source:
//   - password shape (authentik): username + passwordFile | passwordEnv;
//   - secret shape (standard): clientSecretFile | clientSecretEnv, no username.
//
// Anything else is an error rather than a silent pick. The issuer is
// required: the secret must go to the IdP the operator named, not to the one
// the MCP server's metadata names (oauth.Flow.resolveIssuer). Secret files
// need absolute paths: the MCP client starts mcpurl from a directory of its
// own choosing.
func validateGrant(p Profile, noOAuth bool) error {
	sa := p.ServiceAccount
	pwd := countSet(sa.PasswordFile, sa.PasswordEnv)
	sec := countSet(sa.ClientSecretFile, sa.ClientSecretEnv)
	switch sa.Grant {
	case "":
		if sa != (ServiceAccount{}) {
			return fmt.Errorf(`username / passwordFile / passwordEnv / clientSecretFile / clientSecretEnv need grant = %q`, oauth.GrantClientCredentials)
		}
		return nil
	case oauth.GrantClientCredentials:
	default:
		return fmt.Errorf("unknown grant %q (want %q, or none for the browser login)", sa.Grant, oauth.GrantClientCredentials)
	}

	switch {
	case p.ClientID == "":
		return errors.New("grant client_credentials needs clientID: dynamic registration is for browser logins")
	case p.Issuer == "":
		return errors.New("grant client_credentials needs issuer: the service account's secret goes to the IdP named in the profile, never to one the MCP server names")
	case p.BearerEnv != "":
		return errors.New("grant client_credentials conflicts with bearerEnv: pick one")
	case noOAuth:
		return errors.New("grant client_credentials conflicts with --no-oauth")
	case pwd > 1:
		return errors.New("both passwordFile and passwordEnv are set: pick one")
	case sec > 1:
		return errors.New("both clientSecretFile and clientSecretEnv are set: pick one")
	case pwd > 0 && sec > 0:
		return errors.New("both a password and a client secret are set: use username + password (authentik) or a client secret, not both")
	case sa.Username != "" && pwd == 0:
		return fmt.Errorf("username %q needs passwordFile or passwordEnv (the client-secret shape takes no username)", sa.Username)
	case sa.Username == "" && pwd > 0:
		return errors.New("passwordFile / passwordEnv need username")
	case sec == 0 && pwd == 0:
		return errors.New("grant client_credentials needs username + passwordFile | passwordEnv, or clientSecretFile | clientSecretEnv")
	}
	for _, path := range []string{sa.PasswordFile, sa.ClientSecretFile} {
		if path != "" && !filepath.IsAbs(path) {
			return fmt.Errorf("secret file %q must be an absolute path: the MCP client starts mcpurl from its own directory", path)
		}
	}
	return nil
}

func countSet(vals ...string) int {
	n := 0
	for _, v := range vals {
		if v != "" {
			n++
		}
	}
	return n
}

// secretSource is where a service account's secret lives: a file or an env
// var — the app password with a username, the client secret without.
type secretSource struct {
	file, env string
}

func (sa ServiceAccount) secretSource() secretSource {
	if sa.Username != "" {
		return secretSource{file: sa.PasswordFile, env: sa.PasswordEnv}
	}
	return secretSource{file: sa.ClientSecretFile, env: sa.ClientSecretEnv}
}

// String names the source for show — never the value.
func (s secretSource) String() string {
	if s.env != "" {
		return "env " + s.env
	}
	return "file " + s.file
}

// read returns the secret. Called at every mint: a rotated file or a changed
// variable takes effect without a restart. The trailing line break `echo`
// leaves in a file is not part of the secret; anything else is.
func (s secretSource) read() (string, error) {
	if s.env != "" {
		v, err := envValue(s.env)
		if err != nil {
			return "", fmt.Errorf("client_credentials: %w", err)
		}
		return v, nil
	}
	data, err := os.ReadFile(s.file)
	if err != nil {
		return "", fmt.Errorf("client_credentials: %w", err)
	}
	v := strings.TrimRight(string(data), "\r\n")
	if strings.TrimSpace(v) == "" {
		return "", fmt.Errorf("client_credentials: secret file %s is empty", s.file)
	}
	return v, nil
}

// CheckCredentials verifies that the profile's own credential is there — the
// bearer-env variable, the service-account secret — so that a command using
// it fails at start, not at the first 401; it warns about a secret file
// others can read, as ssh does about a private key. Not part of New: logout
// only drops what is stored, and a secret already removed must not block
// cleaning up after it.
func (a *App) CheckCredentials() error {
	if a.prof.BearerEnv != "" {
		if _, err := envValue(a.prof.BearerEnv); err != nil {
			return fmt.Errorf("bearer-env: %w", err)
		}
	}
	if a.prof.Grant != oauth.GrantClientCredentials {
		return nil
	}
	src := a.prof.secretSource()
	if _, err := src.read(); err != nil {
		return err
	}
	if src.file == "" || runtime.GOOS == "windows" {
		return nil
	}
	if fi, err := os.Stat(src.file); err == nil && fi.Mode().Perm()&0o077 != 0 {
		a.warnf("secret file %s is accessible by group/others (mode %04o): chmod 600 it", src.file, fi.Mode().Perm())
	}
	return nil
}

// credentials is the token flow's view of the profile; nil for the browser
// login.
func (p Profile) credentials() *oauth.ClientCredentials {
	if p.Grant != oauth.GrantClientCredentials {
		return nil
	}
	src := p.secretSource()
	return &oauth.ClientCredentials{Username: p.Username, Secret: src.read, SecretSource: src.String()}
}

// subject names whom a minted token was issued to: its JWT claims — decoded
// without signature verification, and labelled so — or, for an opaque token,
// the identity the profile asked for.
func (a *App) subject(t *oauth.Token) string {
	fallback := a.prof.Username
	if fallback == "" {
		fallback = "client " + a.prof.ClientID
	}
	claims, ok := oauth.UnverifiedClaims(t.AccessToken)
	if !ok {
		return fallback
	}
	var parts []string
	for _, k := range []string{"preferred_username", "sub", "aud", "entitlements"} {
		if v, ok := claims[k]; ok {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
	}
	if len(parts) == 0 {
		return fallback
	}
	return strings.Join(parts, " ") + " (JWT claims, signature not verified)"
}
