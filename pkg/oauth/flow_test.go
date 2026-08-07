package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAS is an authorization server with rotating refresh tokens: the grant
// is valid only for the CURRENT refresh token, like Keycloak with "Revoke
// Refresh Token" enabled.
type fakeAS struct {
	srv *httptest.Server

	mu             sync.Mutex
	seq            int
	currentRefresh string
	invalidGrants  atomic.Int32
	refreshCalls   atomic.Int32
	alwaysInvalid  bool
	expiresIn      int64
	grantedScope   string // echoed as the response `scope` when set
}

func newFakeAS(t *testing.T) *fakeAS {
	f := &fakeAS{currentRefresh: "refresh-0", expiresIn: 1}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           f.srv.URL,
			"authorization_endpoint":           f.srv.URL + "/auth",
			"token_endpoint":                   f.srv.URL + "/token",
			"scopes_supported":                 []string{"openid", "profile", "offline_access"},
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" {
			http.Error(w, `{"error":"unsupported_grant_type"}`, http.StatusBadRequest)
			return
		}
		f.refreshCalls.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.alwaysInvalid || r.Form.Get("refresh_token") != f.currentRefresh {
			f.invalidGrants.Add(1)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		f.seq++
		f.currentRefresh = fmt.Sprintf("refresh-%d", f.seq)
		resp := map[string]any{
			"access_token":  fmt.Sprintf("access-%d", f.seq),
			"refresh_token": f.currentRefresh,
			"expires_in":    f.expiresIn,
		}
		if f.grantedScope != "" {
			resp["scope"] = f.grantedScope
		}
		json.NewEncoder(w).Encode(resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// writeFn adapts a func to io.Writer for capturing Flow.Msg output.
type writeFn func([]byte) (int, error)

func (w writeFn) Write(p []byte) (int, error) { return w(p) }

func newTestFlow(t *testing.T, as *fakeAS, dir string) *Flow {
	return &Flow{
		Endpoint: "https://mcp.example.com/mcp",
		ClientID: "test-client",
		Issuer:   as.srv.URL,
		Store:    &FileStore{Dir: dir + "/tokens"},
		LockDir:  dir + "/locks",
		Logf:     t.Logf,
		Msg:      writeFn(func(p []byte) (int, error) { t.Logf("%s", p); return len(p), nil }),
	}
}

func seedToken(t *testing.T, f *Flow) string {
	t.Helper()
	canonical, _ := Canonicalize(f.Endpoint)
	key := Key(canonical, f.ClientID)
	err := f.Store.Save(key, &Token{
		AccessToken:  "access-0",
		RefreshToken: "refresh-0",
		Expiry:       time.Now().Add(-time.Minute), // already expired
	})
	require.NoError(t, err)
	return key
}

// THE regression test (05-plan.md M3): two independent Flow instances (≈ two
// processes sharing only the token dir + lock dir) hammer refresh against an
// AS with rotating refresh tokens. mcp-remote historically lost tokens here.
func TestRefreshRotationRace(t *testing.T) {
	as := newFakeAS(t)
	dir := t.TempDir()
	f1 := newTestFlow(t, as, dir)
	f2 := newTestFlow(t, as, dir)
	key := seedToken(t, f1)

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, f := range []*Flow{f1, f2} {
		wg.Add(1)
		go func(f *Flow) {
			defer wg.Done()
			for range 25 {
				if _, err := f.Token(context.Background(), "", ""); err != nil {
					errs <- fmt.Errorf("Token: %w", err)
					return
				}
			}
		}(f)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.EqualValues(t, 0, as.invalidGrants.Load(),
		"invalid_grant responses — rotation race lost tokens")
	final, err := f1.Store.Load(key)
	require.NoError(t, err)
	as.mu.Lock()
	current := as.currentRefresh
	as.mu.Unlock()
	assert.Equal(t, current, final.RefreshToken, "stored refresh vs server current")
	t.Logf("refresh calls: %d, rotations survived", as.refreshCalls.Load())
}

// "Both tokens expired" (mcp-remote issue #256): must end in exactly ONE
// interactive login, never a loop.
func TestBothExpiredSingleLogin(t *testing.T) {
	as := newFakeAS(t)
	as.alwaysInvalid = true
	dir := t.TempDir()
	f := newTestFlow(t, as, dir)
	seedToken(t, f)

	var logins atomic.Int32
	f.loginFn = func(_ context.Context, _ *discovery, _ []string) (*Token, error) {
		logins.Add(1)
		return &Token{AccessToken: "login-access", RefreshToken: "login-refresh",
			Expiry: time.Now().Add(time.Hour)}, nil
	}

	tok, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Equal(t, "login-access", tok)
	assert.EqualValues(t, 1, logins.Load())

	// Server rejecting even the fresh login token must NOT loop the browser.
	_, err = f.Token(context.Background(), "login-access", "")
	require.Error(t, err, "want give-up error when a freshly logged-in token is rejected")
	assert.EqualValues(t, 1, logins.Load(), "login loop")
}

// An AS that issues no refresh token condemns the user to a browser login per
// restart. That must be said out loud at login, not discovered days later.
func TestLoginWarnsWhenNoRefreshToken(t *testing.T) {
	as := newFakeAS(t)
	// Each login needs its own token dir: a shared one would let the second
	// flow load the first's token and skip login entirely.
	login := func(t *testing.T, issued *Token) string {
		var warnings strings.Builder
		f := newTestFlow(t, as, t.TempDir())
		f.Warnf = func(format string, args ...any) { fmt.Fprintf(&warnings, format, args...) }
		f.loginFn = func(context.Context, *discovery, []string) (*Token, error) { return issued, nil }
		_, err := f.Token(context.Background(), "", "")
		require.NoError(t, err)
		return warnings.String()
	}

	out := login(t, &Token{AccessToken: "login-access", Expiry: time.Now().Add(time.Hour),
		Scopes: []string{"openid", "profile"}})
	assert.Contains(t, out, "no refresh_token")
	assert.Contains(t, out, "offline_access", "the warning must name the fix")
	assert.Contains(t, out, "openid profile", "and the scope actually granted")

	// The happy path stays quiet.
	assert.Empty(t, login(t, &Token{AccessToken: "login-access", RefreshToken: "login-refresh",
		Expiry: time.Now().Add(time.Hour)}))

	// With no Warnf wired the message must fall back to the debug log rather
	// than vanish — the CLI is the only thing that sets Warnf.
	var logged strings.Builder
	f := newTestFlow(t, newFakeAS(t), t.TempDir())
	f.Logf = func(format string, args ...any) { fmt.Fprintf(&logged, format, args...) }
	f.loginFn = func(context.Context, *discovery, []string) (*Token, error) {
		return &Token{AccessToken: "login-access", Expiry: time.Now().Add(time.Hour)}, nil
	}
	_, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	assert.Contains(t, logged.String(), "no refresh_token")
}

// A refresh may come back with fewer scopes than the stored token carried —
// the AS is entitled to narrow them. The stored token must follow the AS,
// not the memory of what was once requested.
func TestRefreshAdoptsGrantedScopes(t *testing.T) {
	as := newFakeAS(t)
	as.grantedScope = "openid profile"
	f := newTestFlow(t, as, t.TempDir())

	canonical, _ := Canonicalize(f.Endpoint)
	key := Key(canonical, f.ClientID)
	require.NoError(t, f.Store.Save(key, &Token{
		AccessToken: "access-0", RefreshToken: "refresh-0",
		Expiry: time.Now().Add(-time.Minute),
		Scopes: []string{"openid", "profile", "offline_access"},
	}))

	_, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	stored, err := f.Store.Load(key)
	require.NoError(t, err)
	assert.Equal(t, []string{"openid", "profile"}, stored.Scopes)

	// Silence means "unchanged" (RFC 6749 §5.1), not "none". Needs its own AS:
	// the one above already rotated past refresh-0, and seedToken plants it.
	f2 := newTestFlow(t, newFakeAS(t), t.TempDir())
	key2 := seedToken(t, f2)
	_, err = f2.Token(context.Background(), "", "")
	require.NoError(t, err)
	stored2, err := f2.Store.Load(key2)
	require.NoError(t, err)
	assert.Empty(t, stored2.Scopes, "seeded token carried none; the AS said nothing")
}

func TestNoClientID(t *testing.T) {
	f := &Flow{Endpoint: "https://x/mcp", Store: &FileStore{Dir: t.TempDir()}}
	_, err := f.Token(context.Background(), "", "")
	require.ErrorContains(t, err, "clientID")
}

// -v output must never contain token material (04-oauth.md redaction AC).
func TestNoTokenMaterialInLogs(t *testing.T) {
	as := newFakeAS(t)
	dir := t.TempDir()
	var logs []string
	var mu sync.Mutex
	f := newTestFlow(t, as, dir)
	capture := func(format string, args ...any) {
		mu.Lock()
		logs = append(logs, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	f.Logf = capture
	f.Msg = writeFn(func(p []byte) (int, error) { capture("%s", p); return len(p), nil })
	seedToken(t, f)

	_, err := f.Token(context.Background(), "", "")
	require.NoError(t, err)
	mu.Lock()
	defer mu.Unlock()
	for _, l := range logs {
		for _, secret := range []string{"access-", "refresh-"} {
			assert.NotContains(t, l, secret, "log line leaks token material")
		}
	}
}
