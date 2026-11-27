// The client_credentials grant (RFC 6749 §4.4): service accounts on machines
// with no browser and no human. There is no refresh token and no interactive
// fallback — a new access token is one POST away, so Flow re-mints where the
// browser flow would refresh or log in.

package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/vmkteam/mcpurl/pkg/redact"
)

// GrantClientCredentials is the grant_type value — and the profile's grant
// setting that selects this mode.
const GrantClientCredentials = "client_credentials"

const (
	// noExpiryLifetime is how long a minted token without expires_in is
	// trusted. Fresh keeps such a token forever, which suits a browser token
	// with a refresh path behind it; nothing refreshes a minted one, and a
	// re-mint is cheap.
	noExpiryLifetime = 5 * time.Minute

	// mintRetryAfter is how long a refused mint is answered from memory:
	// without it every MCP request of a misconfigured bridge POSTs to the
	// token endpoint.
	mintRetryAfter = 30 * time.Second
)

// ClientCredentials is a service-account credential, in one of two shapes:
//   - authentik's: Username plus the account's app password in the form,
//     the client stays public;
//   - the standard one (Keycloak service accounts): no Username, a client
//     secret sent as HTTP Basic (RFC 6749 §2.3.1).
type ClientCredentials struct {
	Username string // "" = client-secret shape

	// Secret returns the app password (with Username) or the client secret.
	// It is called at every mint, so a rotated secret file needs no restart.
	Secret func() (string, error)

	// SecretSource names where Secret reads from — a file path, an env var
	// name; never the secret itself. It is part of the stored token's
	// identity (Flow.identity).
	SecretSource string
}

// mintFailure is a refused mint, remembered until `until` for the secret it
// was refused with: a changed secret is retried at once.
type mintFailure struct {
	err    error
	secret [sha256.Size]byte
	until  time.Time
}

// obtainMinted is obtain for the client_credentials grant, past the reload.
// There is no refresh token to spend and no browser to fall back on, so a
// rejected token this process minted ends the ladder whatever the challenge
// says — "expired" included: a re-mint returns the same kind of token, and
// with no further rung to stop on the ladder would only loop.
func (f *Flow) obtainMinted(ctx context.Context, key, canonical, rejected, challenge string) (string, error) {
	if f.selfIssued(rejected) {
		return "", rejectionError(parseChallenge(challenge), checksMinted)
	}
	t, err := f.mintAndSave(ctx, key, canonical, challenge)
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

// mintAndSave mints a token, stamps and persists it — like loginAndSave, so
// that parallel bridges and `mcpurl token` share one token instead of each
// hitting the token endpoint. Runs under both locks.
func (f *Flow) mintAndSave(ctx context.Context, key, canonical, challenge string) (*Token, error) {
	secret, err := f.Credentials.Secret()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(secret))
	if mf := f.mintFail; mf != nil && mf.secret == sum && time.Now().Before(mf.until) {
		// Say so: whoever reads the IdP's log next will not find this attempt.
		return nil, fmt.Errorf("%w (repeated from memory: the token endpoint is asked again after %s, or at once when the secret changes)",
			mf.err, mf.until.Format(time.TimeOnly))
	}
	f.mintFail = nil

	d, err := f.discover(ctx, challenge)
	if err != nil {
		return nil, err
	}
	t, err := f.mint(ctx, d, canonical, challenge, secret)
	var te *tokenEndpointError
	switch {
	case errors.As(err, &te):
		// Remember only what the AS said: a network error may be gone by the
		// next request.
		err = f.mintError(d, te, secret)
		f.mintFail = &mintFailure{err: err, secret: sum, until: time.Now().Add(mintRetryAfter)}
		return nil, err
	case err != nil:
		return nil, err
	}

	if err := f.Store.Save(key, t); err != nil {
		return nil, fmt.Errorf("persisting minted token: %w", err)
	}
	f.lastMinted = t.AccessToken
	f.cached = t
	f.debugf("token minted, expires %s", t.Expiry.Format(time.RFC3339))
	return t, nil
}

// mint POSTs the client_credentials grant. resource and scopes go as in the
// browser flow: an IdP may hang a property mapping (an audience, a role) on a
// scope such as offline_access, so the scope list matters just as much here.
func (f *Flow) mint(ctx context.Context, d *discovery, canonical, challenge, secret string) (*Token, error) {
	scopes := f.resolveScopes(d, challenge)
	form := url.Values{
		"grant_type":  {GrantClientCredentials},
		paramResource: {canonical},
	}
	if len(scopes) > 0 {
		form.Set(paramScope, strings.Join(scopes, " "))
	}
	clientSecret := secret // the standard shape: HTTP Basic, no credential in the form
	if f.Credentials.Username != "" {
		clientSecret = ""
		form.Set(paramClientID, f.clientID())
		form.Set("username", f.Credentials.Username)
		form.Set("password", secret)
	}
	// Keys only: the form carries the secret.
	f.debugf("client_credentials grant → POST %s (form: %s)",
		d.AS.TokenEndpoint, strings.Join(slices.Sorted(maps.Keys(form)), ", "))

	tr, err := f.postToken(ctx, d.AS.TokenEndpoint, form, clientSecret)
	if err != nil {
		return nil, err
	}
	// A refresh_token is not stored even if the AS sends one (RFC 6749
	// §4.4.3 says it should not): the next token is a re-mint anyway, and an
	// unused credential is best not kept.
	t := &Token{
		AccessToken: tr.AccessToken,
		Expiry:      tr.expiry(),
		Issuer:      d.AS.Issuer,
		ClientID:    f.clientID(),
		Scopes:      grantedScopes(tr.Scope, scopes),
	}
	if t.Expiry.IsZero() {
		t.Expiry = time.Now().Add(noExpiryLifetime)
		if !f.noExpiryWarned {
			f.noExpiryWarned = true
			f.warnf("%s sent no expires_in: client_credentials tokens are treated as valid for %s", d.AS.Issuer, noExpiryLifetime)
		}
	}
	return t, nil
}

// mintError turns a refused mint into something an operator can act on. The
// IdP gives the same answer for several causes — authentik says
// invalid_grant alike to a provider that does not allow the grant, to an
// account not bound to the application and to a wrong password — so the
// message lists them instead of guessing one.
func (f *Flow) mintError(d *discovery, te *tokenEndpointError, secret string) error {
	said := te.Code
	if te.Description != "" {
		said += ": " + te.Description
	}
	// Server free text: no JWT in it, and not the secret the request carried.
	if secret != "" {
		said = strings.ReplaceAll(said, secret, "[redacted]")
	}
	msg := fmt.Sprintf("%s refused the client_credentials grant for client %s (HTTP %d, %s)",
		d.AS.Issuer, f.clientID(), te.Status, redact.Tokens(said))

	ambiguous := []string{errInvalidGrant.Error(), errInvalidClient.Error(), "unauthorized_client", "unsupported_grant_type"}
	if !slices.Contains(ambiguous, te.Code) {
		return errors.New(msg)
	}
	causes := "the client secret is wrong; the client has no service account, or the grant is not enabled for it"
	if f.Credentials.Username != "" {
		causes = fmt.Sprintf("the provider does not allow the client_credentials grant; the account %q is not bound to the application; the app password is wrong or expired",
			f.Credentials.Username)
	}
	return errors.New(msg + " — the IdP does not say which of: " + causes)
}

// UnverifiedClaims decodes the payload of a JWT access token WITHOUT checking
// its signature: for display only — whom `mcpurl login` minted a token for —
// never for a decision. ok is false for an opaque token.
func UnverifiedClaims(accessToken string) (claims map[string]any, ok bool) {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, false
	}
	return claims, true
}
