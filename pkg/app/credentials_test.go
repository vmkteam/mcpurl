package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vmkteam/mcpurl/pkg/oauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const ccGrant = oauth.GrantClientCredentials

func TestValidateGrant(t *testing.T) {
	base := Profile{URL: "https://mcp.example.com/mcp", ClientID: "cli", Issuer: "https://auth.example.com/application/o/mcp/"}
	with := func(sa ServiceAccount, mod ...func(*Profile)) Profile {
		p := base
		p.ServiceAccount = sa
		for _, m := range mod {
			m(&p)
		}
		return p
	}
	tests := []struct {
		name    string
		prof    Profile
		noOAuth bool
		wantErr string // "" = valid
	}{
		{name: "browser login", prof: base},
		{name: "password shape, file", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", PasswordFile: "/p"})},
		{name: "password shape, env", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", PasswordEnv: "P"})},
		{name: "secret shape, file", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretFile: "/s"})},
		{name: "secret shape, env", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretEnv: "S"})},

		{name: "unknown grant", prof: with(ServiceAccount{Grant: "password"}), wantErr: "unknown grant"},
		{name: "fields without grant", prof: with(ServiceAccount{Username: "svc", PasswordFile: "/p"}), wantErr: "need grant"},
		{name: "secret without grant", prof: with(ServiceAccount{ClientSecretEnv: "S"}), wantErr: "need grant"},
		{name: "no clientID", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretEnv: "S"}, func(p *Profile) { p.ClientID = "" }),
			wantErr: "needs clientID"},
		{name: "no issuer", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretEnv: "S"}, func(p *Profile) { p.Issuer = "" }),
			wantErr: "needs issuer"},
		{name: "relative password file", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", PasswordFile: "svc.secret"}),
			wantErr: "must be an absolute path"},
		{name: "relative client secret file", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretFile: "./kc.secret"}),
			wantErr: "must be an absolute path"},
		{name: "with bearerEnv", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretEnv: "S"}, func(p *Profile) { p.BearerEnv = "B" }),
			wantErr: "conflicts with bearerEnv"},
		{name: "with no-oauth", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretEnv: "S"}), noOAuth: true,
			wantErr: "conflicts with --no-oauth"},
		{name: "two password sources", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", PasswordFile: "/p", PasswordEnv: "P"}),
			wantErr: "both passwordFile and passwordEnv"},
		{name: "two secret sources", prof: with(ServiceAccount{Grant: ccGrant, ClientSecretFile: "/s", ClientSecretEnv: "S"}),
			wantErr: "both clientSecretFile and clientSecretEnv"},
		{name: "both shapes", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", PasswordEnv: "P", ClientSecretEnv: "S"}),
			wantErr: "not both"},
		{name: "username without password", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc"}),
			wantErr: "needs passwordFile or passwordEnv"},
		{name: "username with client secret", prof: with(ServiceAccount{Grant: ccGrant, Username: "svc", ClientSecretEnv: "S"}),
			wantErr: "takes no username"},
		{name: "password without username", prof: with(ServiceAccount{Grant: ccGrant, PasswordEnv: "P"}),
			wantErr: "need username"},
		{name: "no credential", prof: with(ServiceAccount{Grant: ccGrant}), wantErr: "needs username"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateGrant(tt.prof, tt.noOAuth)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestSecretSource(t *testing.T) {
	t.Run("env, MY_ first", func(t *testing.T) {
		t.Setenv("MCPURL_TEST_SECRET", "plain")
		src := secretSource{env: "MCPURL_TEST_SECRET"}
		v, err := src.read()
		require.NoError(t, err)
		assert.Equal(t, "plain", v)
		t.Setenv("MY_MCPURL_TEST_SECRET", "mine")
		v, err = src.read()
		require.NoError(t, err)
		assert.Equal(t, "mine", v)

		_, err = secretSource{env: "MCPURL_TEST_UNSET_SECRET"}.read()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "neither MY_MCPURL_TEST_UNSET_SECRET nor MCPURL_TEST_UNSET_SECRET")
	})

	t.Run("file, re-read on every call", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "svc.secret")
		require.NoError(t, os.WriteFile(path, []byte("first\n"), 0o600))
		src := secretSource{file: path}
		v, err := src.read()
		require.NoError(t, err)
		assert.Equal(t, "first", v, "the trailing newline is not part of the secret")

		require.NoError(t, os.WriteFile(path, []byte("rotated"), 0o600))
		v, err = src.read()
		require.NoError(t, err)
		assert.Equal(t, "rotated", v, "rotation must not need a restart")

		require.NoError(t, os.WriteFile(path, []byte("  spaced  \r\n"), 0o600))
		v, err = src.read()
		require.NoError(t, err)
		assert.Equal(t, "  spaced  ", v, "only the line break goes: spaces may be part of a password")

		require.NoError(t, os.WriteFile(path, []byte(" \n"), 0o600))
		_, err = src.read()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is empty")

		_, err = secretSource{file: path + ".missing"}.read()
		require.Error(t, err)
	})
}

// writeServiceConfig points MCPURL_CONFIG at a config with one service
// profile whose secret sits in a file, and HOME at a scratch dir (tokens,
// locks). Returns the secret file path.
func writeServiceConfig(t *testing.T, url string, mode os.FileMode) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	secret := filepath.Join(dir, "svc.secret")
	require.NoError(t, os.WriteFile(secret, []byte("app-pass\n"), 0o600))
	require.NoError(t, os.Chmod(secret, mode))
	cfg := `
[profiles.svc]
url          = "` + url + `"
clientID     = "svc-cli"
issuer       = "https://auth.example.com/application/o/svc/"
grant        = "client_credentials"
username     = "robot"
passwordFile = "` + secret + `"
`
	path := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	t.Setenv("MCPURL_CONFIG", path)
	return secret
}

func TestServiceProfileStartChecks(t *testing.T) {
	secret := writeServiceConfig(t, "https://mcp.example.com/mcp", 0o644)
	check := func(opts Options, msg io.Writer) error {
		t.Helper()
		opts.Target = "@svc"
		a, err := New(opts, msg)
		require.NoError(t, err)
		return a.CheckCredentials()
	}

	var msg bytes.Buffer
	require.NoError(t, check(Options{}, &msg))
	assert.Contains(t, msg.String(), "accessible by group/others", "ssh-style warning")
	assert.NotContains(t, msg.String(), "app-pass")
	a, err := New(Options{Target: "@svc"}, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, ServiceAccount{Grant: ccGrant, Username: "robot", PasswordFile: secret}, a.prof.ServiceAccount,
		"the flattened TOML fields must decode")

	require.NoError(t, os.WriteFile(secret, nil, 0o600))
	require.Error(t, check(Options{}, io.Discard), "an empty secret fails at start, not at the first 401")
	require.Error(t, check(Options{ServiceAccount: ServiceAccount{PasswordFile: secret + ".missing"}}, io.Discard),
		"a flag overrides the profile, and is checked as well")

	_, err = New(Options{Target: "@svc", BearerEnv: "X"}, io.Discard)
	require.Error(t, err, "a structural conflict fails in New already")
}

// install persists the service-account fields, show prints where the secret
// lives but not the secret, and a new credential shape replaces the old one
// whole.
func TestServiceProfileInstallAndShow(t *testing.T) {
	writeConfig(t)
	secret := filepath.Join(t.TempDir(), "svc.secret")
	require.NoError(t, os.WriteFile(secret, []byte("app-pass"), 0o600))
	const issuer = "https://auth.example.com/application/o/svc/"
	opts := Options{Target: "https://mcp.svc.example/mcp", ClientID: "svc-cli", Issuer: issuer,
		ServiceAccount: ServiceAccount{Grant: ccGrant, Username: "robot", PasswordFile: secret}}
	a, err := New(opts, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.ensureProfile(io.Discard, "svc", false))

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Equal(t, opts.ServiceAccount, cfg.Profiles["svc"].ServiceAccount)

	var shown bytes.Buffer
	a, err = New(Options{}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.Show(&shown, "svc"))
	assert.Contains(t, shown.String(), "grant:        client_credentials")
	assert.Contains(t, shown.String(), "username:     robot")
	assert.Contains(t, shown.String(), "secret:       file "+secret+" (value not shown)")
	assert.NotContains(t, shown.String(), "app-pass")

	// Same name, the client-secret shape: nothing of the password shape stays.
	t.Setenv("MCPURL_TEST_CLIENT_SECRET", "s")
	a, err = New(Options{Target: "https://mcp.svc.example/mcp",
		ServiceAccount: ServiceAccount{Grant: ccGrant, ClientSecretEnv: "MCPURL_TEST_CLIENT_SECRET"}, ClientID: "svc-cli", Issuer: issuer}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.ensureProfile(io.Discard, "svc", false))
	cfg, err = Load("")
	require.NoError(t, err)
	p := cfg.Profiles["svc"]
	assert.Equal(t, ServiceAccount{Grant: ccGrant, ClientSecretEnv: "MCPURL_TEST_CLIENT_SECRET"}, p.ServiceAccount)
	require.NoError(t, validateGrant(p, false), "the merged profile must stay valid")

	// A browser-login reinstall without grant flags keeps the service account.
	a, err = New(Options{Target: "https://mcp.svc.example/v2/mcp"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.ensureProfile(io.Discard, "svc", false))
	cfg, err = Load("")
	require.NoError(t, err)
	assert.Equal(t, ccGrant, cfg.Profiles["svc"].Grant)
}

// A secret file given on the command line is pinned to the directory it was
// typed in: install persists the path, and the MCP client runs mcpurl from
// somewhere else.
func TestServiceProfileRelativeSecretFlag(t *testing.T) {
	writeConfig(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "svc.secret"), []byte("app-pass"), 0o600))
	t.Chdir(dir)

	a, err := New(Options{Target: "https://mcp.svc.example/mcp", ClientID: "svc-cli",
		Issuer:         "https://auth.example.com/application/o/svc/",
		ServiceAccount: ServiceAccount{Grant: ccGrant, Username: "robot", PasswordFile: "svc.secret"}}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.ensureProfile(io.Discard, "svc", false))

	cfg, err := Load("")
	require.NoError(t, err)
	stored := cfg.Profiles["svc"].PasswordFile
	assert.True(t, filepath.IsAbs(stored), stored)
	data, err := os.ReadFile(stored)
	require.NoError(t, err)
	assert.Equal(t, "app-pass", string(data), "the stored path names the file install checked")
}

// fakeJWT wraps a claims payload in the JWT shape; nothing verifies it.
func fakeJWT(payload string) string {
	return "eyJhbGciOiJSUzI1NiJ9." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".sig"
}

// login names whom the token was issued to: JWT claims when there are any,
// labelled unverified; otherwise what the profile asked for.
func TestSubject(t *testing.T) {
	withUser := &App{prof: Profile{ClientID: "svc-cli", ServiceAccount: ServiceAccount{Username: "robot"}}}
	secretOnly := &App{prof: Profile{ClientID: "svc-cli"}}

	tests := []struct {
		name  string
		a     *App
		token string
		want  string
	}{
		{"opaque, password shape", withUser, "opaque-token", "robot"},
		{"opaque, secret shape", secretOnly, "opaque-token", "client svc-cli"},
		{"JWT without the claims shown", withUser, fakeJWT(`{"iss":"x"}`), "robot"},
		{"JWT", secretOnly, fakeJWT(`{"sub":"u-1","aud":"mcp"}`), "sub=u-1 aud=mcp (JWT claims, signature not verified)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.a.subject(&oauth.Token{AccessToken: tt.token}))
		})
	}
}

// Claude Code's direct transport cannot log a service account in: the
// snippet must route it through the bridge.
func TestClaudeConfigServiceProfile(t *testing.T) {
	writeServiceConfig(t, "https://mcp.example.com/mcp", 0o600)
	a, err := New(Options{}, io.Discard)
	require.NoError(t, err)
	var out strings.Builder
	require.NoError(t, a.ClaudeConfig(&out, "svc", ""))
	assert.Contains(t, out.String(), "claude mcp add -s user svc -- mcpurl @svc")
	assert.NotContains(t, out.String(), "--transport http")
}

// fakeIDP is an OIDC authorization server on loopback whose token endpoint
// is token (the form already parsed).
func fakeIDP(t *testing.T, token http.HandlerFunc) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "token_endpoint": srv.URL + "/token",
			"authorization_endpoint": srv.URL + "/auth", "code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		token(w, r)
	})
	return srv
}

// Profiles that share URL and client keep their own tokens: two accounts, a
// wrong password next to a good profile of the same account, and a human's
// browser login — and logout drops exactly its own (field test 2026-11-27,
// t-dev / t-badpw).
func TestServiceAccountTokenIsolation(t *testing.T) {
	passwords := map[string]string{"robot": "good-pass", "robot2": "other-pass"}
	var mints atomic.Int32
	srv := fakeIDP(t, func(w http.ResponseWriter, r *http.Request) {
		n := mints.Add(1)
		user := r.PostForm.Get("username")
		if pw, ok := passwords[user]; !ok || pw != r.PostForm.Get("password") {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"access_token": fakeJWT(fmt.Sprintf(`{"sub":%q,"n":%d}`, user, n)), "expires_in": 300})
	})
	endpoint := srv.URL + "/mcp"

	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	secret := func(name, value string) string {
		path := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(path, []byte(value), 0o600))
		return path
	}
	service := func(name, user, passwordFile string) string {
		return fmt.Sprintf("[profiles.%s]\nurl = %q\nclientID = \"svc-cli\"\nissuer = %q\ngrant = \"client_credentials\"\nusername = %q\npasswordFile = %q\n\n",
			name, endpoint, srv.URL, user, passwordFile)
	}
	cfg := service("dev", "robot", secret("good.secret", "good-pass")) +
		service("badpw", "robot", secret("bad.secret", "wrong-pass")) +
		service("other", "robot2", secret("other.secret", "other-pass")) +
		fmt.Sprintf("[profiles.human]\nurl = %q\nclientID = \"svc-cli\"\n", endpoint)
	cfgPath := filepath.Join(dir, "config.toml")
	require.NoError(t, os.WriteFile(cfgPath, []byte(cfg), 0o600))
	t.Setenv("MCPURL_CONFIG", cfgPath)

	// The human logged in through the browser earlier: same URL, same client.
	tokens := &oauth.FileStore{Dir: oauth.TokensDir()}
	humanKey := oauth.Key(endpoint, "svc-cli")
	require.NoError(t, tokens.Save(humanKey, &oauth.Token{AccessToken: "human-access", RefreshToken: "human-refresh",
		Expiry: time.Now().Add(time.Hour)}))

	app := func(name string, msg io.Writer) *App {
		t.Helper()
		a, err := New(Options{Target: "@" + name, NoKeychain: true}, msg)
		require.NoError(t, err)
		return a
	}
	token := func(name string) (string, error) {
		t.Helper()
		return app(name, io.Discard).AccessToken(context.Background())
	}
	sub := func(tok string) any {
		t.Helper()
		claims, ok := oauth.UnverifiedClaims(tok)
		require.True(t, ok)
		return claims["sub"]
	}

	dev, err := token("dev")
	require.NoError(t, err)
	assert.Equal(t, "robot", sub(dev))

	_, err = token("badpw")
	require.Error(t, err, "a wrong password must not serve the token another profile minted")
	assert.Contains(t, err.Error(), "invalid_grant")

	other, err := token("other")
	require.NoError(t, err)
	assert.Equal(t, "robot2", sub(other), "another account gets its own token")

	human, err := token("human")
	require.NoError(t, err)
	assert.Equal(t, "human-access", human, "the browser login keeps its token")

	again, err := token("dev")
	require.NoError(t, err)
	assert.Equal(t, dev, again, "each profile still reuses its own stored token")
	assert.EqualValues(t, 3, mints.Load(), "dev, badpw, other — nothing else")

	files, err := filepath.Glob(filepath.Join(oauth.TokensDir(), "*.json"))
	require.NoError(t, err)
	assert.Len(t, files, 3, "dev, other, human: one token file each")

	var msg bytes.Buffer
	require.NoError(t, app("dev", &msg).Logout())
	assert.Contains(t, msg.String(), "dropped tokens for "+endpoint, "logout finds the service profile's key")
	files, err = filepath.Glob(filepath.Join(oauth.TokensDir(), "*.json"))
	require.NoError(t, err)
	assert.Len(t, files, 2, "logout drops exactly its own token")
	stored, err := tokens.Load(humanKey)
	require.NoError(t, err)
	assert.Equal(t, "human-refresh", stored.RefreshToken, "the human's refresh token survives it all")
}

// The wiring end to end, against a fake AS: the profile's secret reaches the
// token endpoint, `token` prints the minted token, `login` says whom it was
// issued to — and -v output never shows the secret.
func TestServiceAccountEndToEnd(t *testing.T) {
	var (
		mints    atomic.Int32
		password atomic.Value
	)
	jwt := fakeJWT(`{"sub":"u-1","preferred_username":"robot","entitlements":["ops"]}`)
	srv := fakeIDP(t, func(w http.ResponseWriter, r *http.Request) {
		mints.Add(1)
		password.Store(r.PostForm.Get("password"))
		json.NewEncoder(w).Encode(map[string]any{"access_token": jwt, "expires_in": 300})
	})

	secret := writeServiceConfig(t, srv.URL+"/mcp", 0o600) // loopback http: allowed
	var msg bytes.Buffer
	a, err := New(Options{Target: "@svc", Issuer: srv.URL, NoKeychain: true, Verbose: true}, &msg)
	require.NoError(t, err)

	tok, err := a.AccessToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, jwt, tok)
	assert.Equal(t, "app-pass", password.Load())

	_, err = a.Login(context.Background())
	require.NoError(t, err)
	assert.EqualValues(t, 2, mints.Load(), "login mints unconditionally")
	assert.Contains(t, msg.String(), "minted a client_credentials token for preferred_username=robot sub=u-1 entitlements=[ops]")
	assert.Contains(t, msg.String(), "signature not verified")
	assert.NotContains(t, msg.String(), "app-pass")

	files, err := filepath.Glob(filepath.Join(oauth.TokensDir(), "*.json"))
	require.NoError(t, err)
	require.Len(t, files, 1, "the token lands in the file store")
	stored, err := (&oauth.FileStore{Dir: oauth.TokensDir()}).Load(strings.TrimSuffix(filepath.Base(files[0]), ".json"))
	require.NoError(t, err)
	assert.Equal(t, jwt, stored.AccessToken)

	// logout only drops what is stored: a secret already removed must not
	// block cleaning up after it.
	require.NoError(t, os.Remove(secret))
	msg.Reset()
	a, err = New(Options{Target: "@svc", Issuer: srv.URL, NoKeychain: true}, &msg)
	require.NoError(t, err, "logout resolves the profile without its secret")
	require.Error(t, a.CheckCredentials(), "a command that uses the secret still fails at start")
	require.NoError(t, a.Logout())
	assert.Contains(t, msg.String(), "dropped tokens for "+srv.URL+"/mcp")
	files, err = filepath.Glob(filepath.Join(oauth.TokensDir(), "*.json"))
	require.NoError(t, err)
	assert.Empty(t, files)
}
