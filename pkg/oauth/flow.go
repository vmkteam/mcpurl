package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const expirySkew = 60 * time.Second // proactive refresh window (04-oauth.md)

// Flow implements mcp.TokenProvider: in-memory + stored-token fast path,
// flock-single-flight refresh with rotation, deterministic fallthrough to
// exactly one interactive login. This is the part mcp-remote got wrong.
type Flow struct {
	Endpoint     string // MCP endpoint (canonicalized internally)
	ClientID     string
	Scopes       []string // override; empty = discovery-driven
	Issuer       string   // override; skips RFC 9728
	CallbackPort int
	Store        Store
	LockDir      string       // default: LockDir()
	HTTP         *http.Client // nil = http.DefaultClient
	Logf         func(format string, args ...any)
	Warnf        func(format string, args ...any) // operator-facing events; nil = Logf
	Msg          io.Writer                        // user-facing output (browser hint); nil = stderr

	discoMu sync.Mutex
	disco   *discovery

	mu     sync.Mutex // in-process single-flight (flock handles cross-process)
	cached *Token
	// Tokens issued by our own refresh / login in this process: if the server
	// rejects even those, escalate (refresh → login → give up), never loop.
	lastRefreshed string
	lastLoggedIn  string

	loginFn func(ctx context.Context, d *discovery, scopes []string) (*Token, error)
}

// KeyFor derives the token-store key for an endpoint/clientID pair — the
// single place this recipe lives (Flow and `mcpurl logout` both use it).
func KeyFor(endpoint, clientID string) (string, error) {
	canonical, err := Canonicalize(endpoint)
	if err != nil {
		return "", err
	}
	return Key(canonical, clientID), nil
}

// resourceKey is the shared prologue of every Flow entry point: client_id
// guard, canonical endpoint URL, token-store key. Recomputing it per call is
// microseconds — not worth caching state for.
func (f *Flow) resourceKey() (canonical, key string, err error) {
	if f.ClientID == "" {
		return "", "", errors.New("no client_id: set clientID in the profile (DCR not supported in v1)")
	}
	canonical, err = Canonicalize(f.Endpoint)
	if err != nil {
		return "", "", err
	}
	return canonical, Key(canonical, f.ClientID), nil
}

func (f *Flow) lockDir() string {
	if f.LockDir != "" {
		return f.LockDir
	}
	return LockDir()
}

func (f *Flow) httpc() *http.Client {
	if f.HTTP != nil {
		return f.HTTP
	}
	return http.DefaultClient
}

func (f *Flow) debugf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

// warnf reports what an operator must learn without -v (mirrors Bridge.warnf).
func (f *Flow) warnf(format string, args ...any) {
	if f.Warnf != nil {
		f.Warnf(format, args...)
		return
	}
	f.debugf(format, args...)
}

func (f *Flow) printf(format string, args ...any) {
	w := f.Msg
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, format+"\n", args...)
}

// Token implements streamable.TokenProvider (see its contract).
func (f *Flow) Token(ctx context.Context, rejected, challenge string) (string, error) {
	canonical, key, err := f.resourceKey()
	if err != nil {
		return "", err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// Fast path: nothing was rejected and we hold a fresh token. The
	// in-memory copy spares a store read per message (the keychain backend
	// shells out on every Load).
	if rejected == "" {
		if f.cached.Fresh(expirySkew) {
			return f.cached.AccessToken, nil
		}
		if t, err := f.Store.Load(key); err == nil && t.Fresh(expirySkew) {
			f.cached = t
			return t.AccessToken, nil
		}
	}

	var token string
	lockErr := WithLock(ctx, f.lockDir(), key, func() error {
		var err error
		token, err = f.obtain(ctx, key, canonical, rejected, challenge)
		return err
	})
	return token, lockErr
}

// obtain runs under both locks: reload → refresh → interactive, always
// persisting rotated refresh tokens.
func (f *Flow) obtain(ctx context.Context, key, canonical, rejected, challenge string) (string, error) {
	stored, err := f.Store.Load(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}

	// Another process may have refreshed while we waited for the lock.
	if stored.Fresh(expirySkew) && stored.AccessToken != rejected {
		f.cached = stored
		return stored.AccessToken, nil
	}

	d, err := f.discover(ctx, challenge)
	if err != nil {
		return "", err
	}

	// Refresh — unless the rejected token came from our own refresh (then
	// refreshing again is pointless, escalate to login).
	if stored != nil && stored.RefreshToken != "" && (rejected == "" || rejected != f.lastRefreshed) {
		t, rerr := f.refresh(ctx, d, canonical, stored)
		switch {
		case rerr == nil:
			if serr := f.Store.Save(key, t); serr != nil {
				return "", fmt.Errorf("persisting refreshed token: %w", serr)
			}
			f.lastRefreshed = t.AccessToken
			f.cached = t
			f.debugf("token refreshed, expires %s", t.Expiry.Format(time.RFC3339))
			return t.AccessToken, nil
		case errors.Is(rerr, errInvalidGrant):
			f.debugf("refresh token invalid, falling through to interactive login")
			if derr := f.Store.Delete(key); derr != nil {
				f.debugf("deleting stale token: %v", derr)
			}
		default:
			return "", fmt.Errorf("token refresh: %w", rerr)
		}
	}

	// Interactive login — exactly once per rejection cycle.
	if rejected != "" && rejected == f.lastLoggedIn {
		return "", errors.New("server rejects freshly issued tokens; giving up (check client/audience config)")
	}
	t, err := f.loginAndSave(ctx, key, d, challenge)
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

// loginAndSave runs the interactive flow (test hook aware), stamps and
// persists the result — the single post-login bookkeeping site.
func (f *Flow) loginAndSave(ctx context.Context, key string, d *discovery, challenge string) (*Token, error) {
	login := f.loginFn
	if login == nil {
		login = f.browserLogin
	}
	t, err := login(ctx, d, f.resolveScopes(d, challenge))
	if err != nil {
		return nil, err
	}
	t.Issuer, t.ClientID = d.AS.Issuer, f.ClientID
	// No refresh token means this login repeats on every restart once the
	// access token expires. Say so now: the alternative is the user meeting it
	// as a browser popup days later, with nothing to point at.
	if t.RefreshToken == "" {
		f.warnf("%s issued no refresh_token (granted scope: %s) — a new browser login will be needed once this one expires; add %s to the profile scopes, and enable it for client %s",
			d.AS.Issuer, strings.Join(t.Scopes, " "), scopeOffline, f.ClientID)
	}
	if err := f.Store.Save(key, t); err != nil {
		return nil, fmt.Errorf("persisting token after login: %w", err)
	}
	f.lastLoggedIn = t.AccessToken
	f.cached = t
	return t, nil
}

const grantRefreshToken = "refresh_token"

var errInvalidGrant = errors.New("invalid_grant")

// refresh POSTs the refresh_token grant by hand: oauth2.TokenSource cannot
// carry the RFC 8707 resource parameter, and we need rotated refresh tokens
// surfaced verbatim.
func (f *Flow) refresh(ctx context.Context, d *discovery, canonical string, stored *Token) (*Token, error) {
	form := url.Values{
		"grant_type":      {grantRefreshToken},
		grantRefreshToken: {stored.RefreshToken},
		"client_id":       {f.ClientID},
		paramResource:     {canonical},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.AS.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := f.httpc().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var oe struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &oe)
		if oe.Error == "invalid_grant" {
			return nil, errInvalidGrant
		}
		return nil, fmt.Errorf("token endpoint HTTP %d (%s)", resp.StatusCode, oe.Error)
	}

	var tr struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("bad token response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, errors.New("token response has no access_token")
	}

	t := &Token{
		AccessToken:  tr.AccessToken,
		RefreshToken: stored.RefreshToken, // keep unless rotated
		Issuer:       d.AS.Issuer,
		ClientID:     f.ClientID,
		Scopes:       grantedScopes(tr.Scope, stored.Scopes),
	}
	if tr.RefreshToken != "" {
		t.RefreshToken = tr.RefreshToken // ALWAYS take the rotated one
	}
	if tr.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	return t, nil
}

// grantedScopes prefers the AS's `scope` response over what was requested —
// they differ whenever the AS silently drops scopes the client is not
// configured for (authentik intersects the request with the provider's scope
// mappings, so a requested offline_access can vanish). Storing the request
// would make the token claim capabilities it does not have. RFC 6749 §5.1
// permits omitting the field when it matches the request, hence the fallback.
func grantedScopes(respScope string, requested []string) []string {
	if respScope == "" {
		return requested
	}
	return strings.Fields(respScope)
}

// Login runs the interactive browser flow unconditionally (CLI `mcpurl
// login`), persisting the result.
func (f *Flow) Login(ctx context.Context) (*Token, error) {
	canonical, key, err := f.resourceKey()
	if err != nil {
		return nil, err
	}

	// Discovery may need the 401 challenge; probe the endpoint for one.
	challenge := f.probeChallenge(ctx, canonical)
	d, err := f.discover(ctx, challenge)
	if err != nil {
		return nil, err
	}

	var out *Token
	f.mu.Lock()
	defer f.mu.Unlock()
	lockErr := WithLock(ctx, f.lockDir(), key, func() error {
		t, err := f.loginAndSave(ctx, key, d, challenge)
		if err != nil {
			return err
		}
		out = t
		return nil
	})
	return out, lockErr
}

// probeChallenge POSTs a harmless request to collect the WWW-Authenticate
// header (best effort — discovery falls back to well-known probing). The
// body is deliberately empty: auth middleware challenges before parsing.
func (f *Flow) probeChallenge(ctx context.Context, canonical string) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, canonical, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := f.httpc().Do(req)
	if err != nil {
		return ""
	}
	drainBody(resp)
	return resp.Header.Get("WWW-Authenticate")
}

// drainBody discards a bounded remainder and closes (keep-alive hygiene).
func drainBody(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
}
