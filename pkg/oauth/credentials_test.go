package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientCredentials is the fake AS's client_credentials grant: authentik's
// username + app password in the form, or the standard client secret over
// HTTP Basic (§2.3.1-encoded) when ccUser is empty.
func (f *fakeAS) clientCredentials(w http.ResponseWriter, r *http.Request) {
	f.mints.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ccForm = r.PostForm
	id, secret, basic := r.BasicAuth()
	f.ccBasicID, _ = url.QueryUnescape(id)
	f.ccBasicSecret, _ = url.QueryUnescape(secret)

	refuse := func(code, desc string) {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
	}
	switch {
	case f.ccRedirect != "":
		http.Redirect(w, r, f.ccRedirect, http.StatusTemporaryRedirect)
		return
	case f.ccErr != "":
		refuse(f.ccErr, f.ccErrDesc)
		return
	case f.ccUser != "" && (basic || r.PostForm.Get("username") != f.ccUser || r.PostForm.Get("password") != f.ccSecret):
		refuse("invalid_grant", "")
		return
	case f.ccUser == "" && (!basic || f.ccBasicSecret != f.ccSecret):
		refuse("invalid_client", "")
		return
	}
	f.seq++
	resp := map[string]any{"access_token": fmt.Sprintf("minted-%d", f.seq), "token_type": "Bearer"}
	if !f.ccNoExpiry {
		resp["expires_in"] = f.expiresIn
	}
	json.NewEncoder(w).Encode(resp)
}

// newCCFlow is a client_credentials Flow whose secret the test can change
// between calls, and whose browser login fails the test if anything reaches
// it — loginFn is the only way there. The endpoint sits on the fake AS: this
// mode always reads the PRM document, and that must stay on loopback.
func newCCFlow(t *testing.T, as *fakeAS, dir, user string, secret *string) *Flow {
	t.Helper()
	f := newTestFlow(t, as, dir)
	f.Endpoint = as.srv.URL + "/mcp"
	f.Credentials = &ClientCredentials{Username: user, Secret: func() (string, error) { return *secret, nil }}
	f.loginFn = func(context.Context, *discovery, []string) (*Token, error) {
		t.Error("client_credentials reached the browser login")
		return nil, errors.New("no browser here")
	}
	return f
}

func newCCAS(t *testing.T, user, secret string) *fakeAS {
	t.Helper()
	as := newFakeAS(t)
	as.ccUser, as.ccSecret, as.expiresIn = user, secret, 3600
	return as
}

// The authentik shape: the form carries everything, the token is stored and
// shared — neither this process nor another one mints again while it is fresh.
func TestClientCredentialsMint(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	dir := t.TempDir()
	f := newCCFlow(t, as, dir, "svc", &secret)

	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)

	as.mu.Lock()
	form := as.ccForm
	as.mu.Unlock()
	assert.Equal(t, GrantClientCredentials, form.Get("grant_type"))
	assert.Equal(t, "test-client", form.Get("client_id"))
	assert.Equal(t, "svc", form.Get("username"))
	assert.Equal(t, "app-pass", form.Get("password"))
	assert.Equal(t, "openid profile offline_access", form.Get("scope"),
		"scopes as for the browser login, offline_access included: IdP mappings hang on it")
	assert.Equal(t, as.srv.URL+"/mcp", form.Get("resource"))

	stored, err := f.Store.Load(flowKey(f))
	require.NoError(t, err)
	assert.Equal(t, "minted-1", stored.AccessToken)
	assert.Empty(t, stored.RefreshToken)
	assert.WithinDuration(t, time.Now().Add(time.Hour), stored.Expiry, time.Minute)

	tok, err = f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)
	other := newCCFlow(t, as, dir, "svc", &secret) // ≈ a second bridge process
	tok, err = other.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)
	assert.EqualValues(t, 1, as.mints.Load(), "a fresh stored token must be reused")
}

// The standard shape: client secret over HTTP Basic, form-urlencoded first
// (RFC 6749 §2.3.1), and no credential in the form.
func TestClientCredentialsSecretShape(t *testing.T) {
	secret := "s:e+c%r/et ü"
	as := newCCAS(t, "", secret)
	f := newCCFlow(t, as, t.TempDir(), "", &secret)

	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)

	as.mu.Lock()
	defer as.mu.Unlock()
	assert.Equal(t, "test-client", as.ccBasicID)
	assert.Equal(t, secret, as.ccBasicSecret, "the secret must round-trip through the §2.3.1 encoding")
	for _, k := range []string{"client_id", "username", "password", "client_secret"} {
		assert.NotContains(t, as.ccForm, k, "one client authentication method per request")
	}
}

// Re-mint ahead of expiry, and a token without expires_in must not live
// forever: nothing refreshes it.
func TestClientCredentialsExpiry(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	as.expiresIn = 30 // inside expirySkew: stale as soon as it is issued
	f := newCCFlow(t, as, t.TempDir(), "svc", &secret)

	for range 2 {
		_, err := f.Token(context.Background(), "", "")
		require.NoError(t, err)
	}
	assert.EqualValues(t, 2, as.mints.Load(), "a token inside the skew window is re-minted")

	as.ccNoExpiry = true
	var warnings []string
	f2 := newCCFlow(t, as, t.TempDir(), "svc", &secret)
	f2.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
	_, err := f2.Token(context.Background(), "", "")
	require.NoError(t, err)
	stored, err := f2.Store.Load(flowKey(f2))
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(noExpiryLifetime), stored.Expiry, 5*time.Second)
	require.Len(t, warnings, 1)
	assert.Contains(t, warnings[0], "no expires_in")
}

// A 401 on a stored token costs one mint; a 401 on the token just minted is
// the end — also when the server calls it expired, the case where the browser
// flow still escalates.
func TestClientCredentialsRejection(t *testing.T) {
	const expired = `Bearer error="invalid_token", error_description="The access token expired"`
	secret := "app-pass"

	t.Run("stored token, then the minted one", func(t *testing.T) {
		as := newCCAS(t, "svc", secret)
		f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
		require.NoError(t, f.Store.Save(flowKey(f), &Token{AccessToken: "stored", Expiry: time.Now().Add(time.Hour)}))

		tok, err := f.Token(context.Background(), "", "")
		require.NoError(t, err)
		assert.Equal(t, "stored", tok)
		assert.Zero(t, as.mints.Load())

		tok, err = f.Token(context.Background(), "stored", expired)
		require.NoError(t, err)
		assert.Equal(t, "minted-1", tok)

		_, err = f.Token(context.Background(), "minted-1", expired)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clocks", "an expired-on-arrival token points at the clocks")
		assert.Contains(t, err.Error(), "token expired", "and quotes the server")
		assert.EqualValues(t, 1, as.mints.Load())
	})

	t.Run("just minted", func(t *testing.T) {
		as := newCCAS(t, "svc", secret)
		f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
		tok, err := f.Token(context.Background(), "", "")
		require.NoError(t, err)
		_, err = f.Token(context.Background(), tok, expired)
		require.Error(t, err)
		assert.EqualValues(t, 1, as.mints.Load(), "exactly one POST, no retry")
	})
}

// A refused mint: one descriptive error that lists the causes the IdP will
// not tell apart, remembered so that each MCP request does not POST again —
// until the secret changes.
func TestClientCredentialsRefused(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", "other-pass")
	f := newCCFlow(t, as, t.TempDir(), "svc", &secret)

	_, err := f.Token(context.Background(), "", "")
	require.Error(t, err)
	for _, want := range []string{"invalid_grant", "does not allow the client_credentials grant", `"svc" is not bound`, "app password is wrong"} {
		assert.Contains(t, err.Error(), want)
	}

	_, err2 := f.Token(context.Background(), "", "")
	require.Error(t, err2)
	assert.Contains(t, err2.Error(), err.Error())
	assert.Contains(t, err2.Error(), "repeated from memory", "an attempt missing from the IdP's log must be explained")
	assert.EqualValues(t, 1, as.mints.Load(), "a refusal is answered from memory")

	secret = "other-pass" // rotated: retried at once
	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)
	assert.EqualValues(t, 2, as.mints.Load())

	// The secret shape names its own causes.
	sec := "wrong"
	f2 := newCCFlow(t, newCCAS(t, "", "right"), t.TempDir(), "", &sec)
	_, err = f2.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_client")
	assert.Contains(t, err.Error(), "client secret is wrong")
}

// The secret goes to the token endpoint and nowhere else: not into -v output,
// warnings, user messages — nor into an error, even when the server pastes it
// into its error_description.
func TestClientCredentialsSecretNeverLeaks(t *testing.T) {
	secret := "S3cr3t-App-Pass"
	as := newCCAS(t, "svc", secret)
	as.ccNoExpiry = true // exercises the warning path too
	minting := newCCFlow(t, as, t.TempDir(), "svc", &secret)
	refused := newCCFlow(t, as, t.TempDir(), "svc", &secret)
	logs := captureOutput(minting, refused)

	_, err := minting.Token(context.Background(), "", "")
	require.NoError(t, err)

	as.ccErr, as.ccErrDesc = "invalid_grant", "bad password "+secret
	_, err = refused.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "bad password [redacted]")

	require.NotEmpty(t, logs())
	joined := strings.Join(logs(), "\n")
	assert.NotContains(t, joined, secret)
	assert.Contains(t, joined, "form: client_id, grant_type, password, resource, scope, username",
		"-v shows the form keys, never the values")
}

// A service profile and a human profile of the same server share URL and
// public client_id. They must not share the stored token: the service would
// act with the human's entitlements, and its mint would drop the human's
// refresh token.
func TestClientCredentialsStoreIsolation(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	dir := t.TempDir()
	human := newTestFlow(t, as, dir)
	human.Endpoint = as.srv.URL + "/mcp"
	humanKey := flowKey(human)
	humanTok := &Token{AccessToken: "human-access", RefreshToken: "human-refresh", Expiry: time.Now().Add(time.Hour)}
	require.NoError(t, human.Store.Save(humanKey, humanTok))

	svc := newCCFlow(t, as, dir, "svc", &secret)
	tok, err := svc.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok, "the human's token is not the service's")

	stored, err := human.Store.Load(humanKey)
	require.NoError(t, err)
	assert.Equal(t, "human-refresh", stored.RefreshToken, "the mint must not touch the human's token")

	// The same account reading its secret elsewhere is another profile: with
	// a wrong password there it must fail, not borrow svc's fresh token.
	wrong := "wrong-pass"
	badPw := newCCFlow(t, as, dir, "svc", &wrong)
	badPw.Credentials.SecretSource = "file /etc/mcpurl/bad.secret"
	_, err = badPw.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid_grant")

	dropped, _, err := svc.Forget()
	require.NoError(t, err)
	assert.True(t, dropped)
	tok, err = human.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "human-access", tok, "logout of the service leaves the human")

	// Two service accounts on one client are two identities as well.
	other := newCCFlow(t, as, dir, "svc2", &secret)
	assert.NotEqual(t, flowKey(svc), flowKey(other))
}

// `mcpurl login` in this mode mints — no browser, no callback listener.
func TestClientCredentialsLogin(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	f := newCCFlow(t, as, t.TempDir(), "svc", &secret)

	tok, err := f.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok.AccessToken)
	assert.EqualValues(t, 1, as.mints.Load())

	tok, err = f.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "minted-2", tok.AccessToken, "login mints unconditionally, as the browser login logs in")
}

// An AS for machine clients only may publish no authorization endpoint and
// no PKCE: the grant does not need them. The browser flow still refuses.
func TestClientCredentialsMachineOnlyAS(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	as.m2mOnly = true

	tok, err := newCCFlow(t, as, t.TempDir(), "svc", &secret).Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)

	browser := newTestFlow(t, as, t.TempDir())
	browser.loginFn = func(context.Context, *discovery, []string) (*Token, error) {
		t.Error("discovery must refuse before any login")
		return nil, errors.New("unreachable")
	}
	_, err = browser.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "lacks endpoints")
}

// The secret goes to the configured issuer only. The PRM document belongs to
// the MCP server: it still supplies the scopes, but naming another
// authorization server gets it refused, not followed.
func TestClientCredentialsPinnedIssuer(t *testing.T) {
	secret := "app-pass"

	t.Run("no issuer", func(t *testing.T) {
		as := newCCAS(t, "svc", secret)
		f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
		f.Issuer = ""
		_, err := f.Token(context.Background(), "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "needs a configured issuer")
		assert.Zero(t, as.mints.Load())
	})

	t.Run("PRM agrees: its scopes are used", func(t *testing.T) {
		as := newCCAS(t, "svc", secret)
		as.prmAS = as.srv.URL + "/" // a trailing slash is the same issuer
		f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
		_, err := f.Token(context.Background(), "", "")
		require.NoError(t, err)
		as.mu.Lock()
		defer as.mu.Unlock()
		assert.Equal(t, "openid entitlements offline_access", as.ccForm.Get("scope"),
			"a pinned issuer must not cost the PRM scopes — the role claim may hang on one")
	})

	t.Run("PRM names another AS", func(t *testing.T) {
		as := newCCAS(t, "svc", secret)
		as.prmAS = "https://evil.example"
		f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
		_, err := f.Token(context.Background(), "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "names authorization server https://evil.example")
		assert.Zero(t, as.mints.Load(), "nothing may be sent once the server disagrees")
	})
}

// A token endpoint answering 307 must not get the form re-sent to the
// Location: http.Client would forward the password to any host.
func TestTokenEndpointRedirectNotFollowed(t *testing.T) {
	var forwarded atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		forwarded.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	as.ccRedirect = elsewhere.URL + "/collect"
	_, err := newCCFlow(t, as, t.TempDir(), "svc", &secret).Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 307")
	assert.Zero(t, forwarded.Load(), "the form must not follow the redirect")
}

// failingTransport fails requests to one path while fail is set — a network
// error, not an answer from the AS.
type failingTransport struct {
	path string
	fail atomic.Bool
}

func (t *failingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.fail.Load() && r.URL.Path == t.path {
		return nil, errors.New("connection reset by peer")
	}
	return http.DefaultTransport.RoundTrip(r)
}

// Only a refusal is remembered: a network error may be gone by the next
// request, and must not hold the bridge down for the retry window.
func TestClientCredentialsNetworkErrorNotRemembered(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	tr := &failingTransport{path: "/token"}
	tr.fail.Store(true)
	f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
	f.HTTP = &http.Client{Transport: tr}

	_, err := f.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection reset")

	tr.fail.Store(false)
	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "minted-1", tok)
}

// Dynamic registration creates a browser-login client: a service account
// without a configured client_id must fail, not register one.
func TestClientCredentialsNeverRegisters(t *testing.T) {
	secret := "app-pass"
	as := newCCAS(t, "svc", secret)
	as.dcr = true
	f := newCCFlow(t, as, t.TempDir(), "svc", &secret)
	f.ClientID = ""

	_, err := f.Token(context.Background(), "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "needs a configured client_id")
	assert.Zero(t, as.registrations.Load())
	assert.Zero(t, as.mints.Load())
}

func TestUnverifiedClaims(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"u1","entitlements":["mcp-oncall"]}`))
	claims, ok := UnverifiedClaims("eyJhbGciOiJSUzI1NiJ9." + payload + ".sig")
	require.True(t, ok)
	assert.Equal(t, "u1", claims["sub"])
	assert.Equal(t, []any{"mcp-oncall"}, claims["entitlements"])

	for _, opaque := range []string{"opaque-token", "a.b", "a.!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("[1]")) + ".c"} {
		_, ok := UnverifiedClaims(opaque)
		assert.False(t, ok, opaque)
	}
}
