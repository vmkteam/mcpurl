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

	"github.com/vmkteam/mcpurl/pkg/redact"
)

const expirySkew = 60 * time.Second // proactive refresh window (04-oauth.md)

// Flow implements mcp.TokenProvider: in-memory + stored-token fast path,
// flock-single-flight refresh with rotation, deterministic fallthrough to
// exactly one interactive login. This is the part mcp-remote got wrong.
type Flow struct {
	Endpoint     string   // MCP endpoint (canonicalized internally)
	ClientID     string   // empty = dynamic client registration (register.go)
	Scopes       []string // override; empty = discovery-driven
	Issuer       string   // override; skips RFC 9728
	CallbackPort int
	Store        Store
	Clients      *ClientStore // dynamic registrations; nil = ClientsDir()
	LockDir      string       // default: LockDir()
	HTTP         *http.Client // nil = http.DefaultClient
	Logf         func(format string, args ...any)
	Warnf        func(format string, args ...any) // operator-facing events; nil = Logf
	Msg          io.Writer                        // user-facing output (browser hint); nil = stderr

	discoMu sync.Mutex
	disco   *discovery

	mu     sync.Mutex // in-process single-flight (flock handles cross-process)
	cached *Token
	reg    *Registration // dynamic registration in use; nil with a configured ClientID
	// Tokens issued by our own refresh / login in this process: if the server
	// rejects even those, escalate (refresh → login → give up), never loop.
	lastRefreshed string
	lastLoggedIn  string

	loginFn func(ctx context.Context, d *discovery, scopes []string) (*Token, error)
}

// resourceKey is the shared prologue of every Flow entry point: canonical
// endpoint URL, client_id, token-store key. Without a configured client_id
// it picks up a dynamic registration stored by an earlier run (one file read
// per process); with none it answers errNoClient — ensureClient registers.
// A registration that fails to load still yields canonical: Forget drops it.
// Caller holds f.mu.
func (f *Flow) resourceKey() (canonical, key string, err error) {
	canonical, err = Canonicalize(f.Endpoint)
	if err != nil {
		return "", "", err
	}
	if f.ClientID == "" && f.reg == nil {
		reg, err := f.clients().Load(f.clientKey(canonical))
		switch {
		case errors.Is(err, ErrNotFound):
			return canonical, "", errNoClient
		case err != nil:
			return canonical, "", err
		}
		f.reg = reg
	}
	return canonical, Key(canonical, f.clientID()), nil
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
	f.mu.Lock()
	defer f.mu.Unlock()

	token, err := f.token(ctx, rejected, challenge)
	if errors.Is(err, errClientGone) {
		// The dynamic registration was dropped: this round registers anew, and
		// with no token stored for the new client it ends in one login.
		token, err = f.token(ctx, rejected, challenge)
	}
	return token, err
}

// token is one round of Token, under f.mu.
func (f *Flow) token(ctx context.Context, rejected, challenge string) (string, error) {
	canonical, key, err := f.ensureClient(ctx, challenge)
	if err != nil {
		return "", err
	}

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

	ch := parseChallenge(challenge)

	// A 401 on a token this process just minted is not a stale credential: the
	// authorization server issues it happily and the resource server refuses
	// it (signing algorithm, audience/resource, issuer, clock). Another
	// refresh returns the same kind of token, and a browser login returns the
	// same kind again — the only thing an escalation buys the user here is a
	// pointless login window (docs/tasks/02-401-body-discarded.md).
	if f.selfIssued(rejected) && !ch.staleToken() {
		return "", rejectionError(ch)
	}

	d, err := f.discover(ctx, challenge)
	if err != nil {
		return "", err
	}
	if f.foreignClient(d) {
		return "", f.dropClient(ctx, canonical, key, "registered at "+f.reg.Issuer+", not at "+d.AS.Issuer)
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
		case errors.Is(rerr, errInvalidClient) && f.reg != nil:
			// The server no longer knows the dynamic registration (a reset
			// base, an expired client): a static client_id has no such cure.
			return "", f.dropClient(ctx, canonical, key, d.AS.Issuer+" answers invalid_client")
		default:
			return "", fmt.Errorf("token refresh: %w", rerr)
		}
	}

	// Interactive login — at most one browser window per process, whatever the
	// challenge claims.
	if rejected != "" && rejected == f.lastLoggedIn {
		return "", rejectionError(ch)
	}
	t, err := f.loginAndSave(ctx, key, d, challenge)
	if err != nil {
		return "", err
	}
	return t.AccessToken, nil
}

// selfIssued reports that the rejected token is one this process obtained —
// out of a refresh or a login — rather than one loaded from the store. The
// anonymous marker "-" (see mcp.TokenProvider) never matches: both fields
// only ever hold real access tokens.
func (f *Flow) selfIssued(rejected string) bool {
	return rejected != "" && (rejected == f.lastRefreshed || rejected == f.lastLoggedIn)
}

// rejectionError names the disagreement instead of the symptom: the token is
// structurally valid by construction, so the two servers disagree about what
// a valid token looks like.
func rejectionError(ch bearerChallenge) error {
	msg := "server rejects freshly issued tokens; giving up — the authorization server and the resource server disagree (check the token signing algorithm, the audience/resource, and the issuer)"
	if d := ch.detail(); d != "" {
		msg += "; server said: " + d
	}
	return errors.New(msg)
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
	t.Issuer, t.ClientID = d.AS.Issuer, f.clientID()
	// No refresh token means this login repeats on every restart once the
	// access token expires. Say so now: the alternative is the user meeting it
	// as a browser popup days later, with nothing to point at.
	if t.RefreshToken == "" {
		f.warnf("%s issued no refresh_token (granted scope: %s) — a new browser login will be needed once this one expires; add %s to the profile scopes, and enable it for client %s",
			d.AS.Issuer, strings.Join(t.Scopes, " "), scopeOffline, f.clientID())
	}
	if err := f.Store.Save(key, t); err != nil {
		return nil, fmt.Errorf("persisting token after login: %w", err)
	}
	f.lastLoggedIn = t.AccessToken
	f.cached = t
	return t, nil
}

const grantRefreshToken = "refresh_token"

var (
	errInvalidGrant  = errors.New("invalid_grant")
	errInvalidClient = errors.New("invalid_client")
)

// refresh POSTs the refresh_token grant by hand: oauth2.TokenSource cannot
// carry the RFC 8707 resource parameter, and we need rotated refresh tokens
// surfaced verbatim.
func (f *Flow) refresh(ctx context.Context, d *discovery, canonical string, stored *Token) (*Token, error) {
	form := url.Values{
		"grant_type":      {grantRefreshToken},
		grantRefreshToken: {stored.RefreshToken},
		"client_id":       {f.clientID()},
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
		switch oe.Error {
		case errInvalidGrant.Error():
			return nil, errInvalidGrant
		case errInvalidClient.Error():
			return nil, fmt.Errorf("token endpoint HTTP %d (%w)", resp.StatusCode, errInvalidClient)
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
		ClientID:     f.clientID(),
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
	canonical, err := Canonicalize(f.Endpoint)
	if err != nil {
		return nil, err
	}

	// Discovery may need the 401 challenge; probe the endpoint for one.
	challenge := f.probeChallenge(ctx, canonical)
	d, err := f.discover(ctx, challenge)
	if err != nil {
		return nil, err
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	_, key, err := f.ensureClient(ctx, challenge)
	if err == nil && f.foreignClient(d) {
		err = f.dropClient(ctx, canonical, key, "registered at "+f.reg.Issuer+", not at "+d.AS.Issuer)
		if errors.Is(err, errClientGone) {
			_, key, err = f.ensureClient(ctx, challenge)
		}
	}
	if err != nil {
		return nil, err
	}

	var out *Token
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
	challenge := resp.Header.Get("WWW-Authenticate")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, probeBodyLimit))
	resp.Body.Close()
	// The probe's own 401 explains as much as the bridge's does — dropping it
	// is what sends users to the server's logs for a diagnosis they were
	// already handed. %q keeps it to one line and escapes anything binary;
	// only the logged copy is redacted, discovery still gets the raw header.
	f.debugf("challenge probe → %d, WWW-Authenticate: %q, body: %.512q",
		resp.StatusCode, redact.Tokens(challenge), redact.Tokens(string(body)))
	return challenge
}

// probeBodyLimit doubles as the keep-alive drain bound (see drainBody).
const probeBodyLimit = 4 << 10

// drainBody discards a bounded remainder and closes (keep-alive hygiene).
func drainBody(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, probeBodyLimit))
	resp.Body.Close()
}
