package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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
		json.NewEncoder(w).Encode(map[string]any{
			"access_token":  fmt.Sprintf("access-%d", f.seq),
			"refresh_token": f.currentRefresh,
			"expires_in":    f.expiresIn,
		})
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
