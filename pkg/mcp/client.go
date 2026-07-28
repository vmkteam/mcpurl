// Client is the HTTP side of the bridge: Streamable HTTP POST/GET/DELETE
// against a single MCP endpoint, SSE parsing and session state. It never
// inspects JSON-RPC payloads beyond compacting SSE-assembled bytes; protocol
// logic (initialize interception, re-init, replay) lives in bridge.go.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenProvider supplies the Authorization bearer value.
//
// rejected is "" on the first call for a request; when the server answered
// 401 it is the token that was just rejected — the provider must not return
// it again (it refreshes, escalates to interactive login, or fails). If the
// rejected request carried no token at all, rejected is the marker "-": any
// non-empty value signals escalation, never a first call.
// challenge carries the WWW-Authenticate header of the 401 response, if any
// (used for RFC 9728 discovery).
type TokenProvider interface {
	Token(ctx context.Context, rejected, challenge string) (string, error)
}

// StaticToken is a TokenProvider for --bearer-env style fixed credentials.
type StaticToken string

func (t StaticToken) Token(_ context.Context, rejected, _ string) (string, error) {
	if rejected != "" {
		return "", errors.New("server rejected static bearer credentials")
	}
	return string(t), nil
}

// HTTPError is returned by Post for non-2xx responses that the transport
// layer does not resolve itself.
type HTTPError struct {
	Status int
	Body   []byte
}

func (e *HTTPError) Error() string { return fmt.Sprintf("upstream HTTP %d", e.Status) }

// AuthError wraps a TokenProvider failure — maps to exit code 3.
type AuthError struct{ Err error }

func (e *AuthError) Error() string { return "auth: " + e.Err.Error() }
func (e *AuthError) Unwrap() error { return e.Err }

// ErrNoStream is returned by Listen when the server does not offer a
// server→client stream (405, or 404 without an active session).
var ErrNoStream = errors.New("server does not offer a listening stream")

// ErrSessionExpired is returned when the server answered 404 to a request
// carrying a session id — the caller must re-initialize (MCP 2025-06-18).
var ErrSessionExpired = errors.New("session expired (HTTP 404)")

// Client talks Streamable HTTP to one MCP endpoint.
type Client struct {
	Endpoint string
	HTTP     *http.Client
	Tokens   TokenProvider // nil = no Authorization header
	Headers  http.Header   // extra headers (--header), applied to every request
	Logf     func(format string, args ...any)

	mu          sync.Mutex
	sessionID   string
	protocolVer string
	lastEventID string
}

// DefaultHTTPClient returns a client with connect/TLS timeouts only — no
// overall response timeout, long-running tools are legitimate.
func DefaultHTTPClient(connectTimeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: connectTimeout}).DialContext,
			TLSHandshakeTimeout:   connectTimeout,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
	}
}

func (c *Client) debugf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

// session returns the current Mcp-Session-Id ("" if none assigned).
func (c *Client) session() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionID
}

// clearSession drops the session id (server said 404 — bridge re-inits) and
// the SSE cursor: Last-Event-ID is per-stream, replaying an id from a dead
// session against the new one would ask the server to resume a foreign stream.
func (c *Client) clearSession() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sessionID = ""
	c.lastEventID = ""
}

// setProtocolVersion records the negotiated version; sent as
// MCP-Protocol-Version on subsequent requests.
func (c *Client) setProtocolVersion(v string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.protocolVer = v
}

func (c *Client) prepare(req *http.Request, token string) {
	for k, vs := range c.Headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	c.mu.Lock()
	if c.sessionID != "" {
		req.Header.Set("Mcp-Session-Id", c.sessionID)
	}
	if c.protocolVer != "" {
		// Spec spells it MCP-Protocol-Version; net/http canonicalizes the
		// wire form either way, headers are case-insensitive.
		req.Header.Set("Mcp-Protocol-Version", c.protocolVer)
	}
	c.mu.Unlock()
}

func (c *Client) captureSession(resp *http.Response) {
	id := resp.Header.Get("Mcp-Session-Id")
	if id == "" {
		return
	}
	// Spec: session id MUST be visible ASCII (0x21–0x7E); reject anything
	// else instead of echoing it back into a header on every request.
	for i := range len(id) {
		if id[i] < 0x21 || id[i] > 0x7E {
			c.debugf("ignoring invalid Mcp-Session-Id from server")
			return
		}
	}
	c.mu.Lock()
	c.sessionID = id
	c.mu.Unlock()
}

// token obtains a bearer value, cycling through the provider on rejection.
func (c *Client) token(ctx context.Context, rejected, challenge string) (string, error) {
	if c.Tokens == nil {
		return "", nil
	}
	return c.Tokens.Token(ctx, rejected, challenge)
}

// doAuthed obtains a token, performs the request built by build, and cycles
// the TokenProvider on 401 (up to two fresh tokens — refresh, then
// interactive). Returns the first non-401 response.
func (c *Client) doAuthed(ctx context.Context, build func(token string) (*http.Request, error)) (*http.Response, error) {
	token, err := c.token(ctx, "", "")
	if err != nil {
		return nil, &AuthError{err}
	}
	for attempt := 0; ; attempt++ {
		req, err := build(token)
		if err != nil {
			return nil, err
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", req.Method, c.Endpoint, err)
		}
		c.debugf("%s → %d %s", req.Method, resp.StatusCode, resp.Header.Get("Content-Type"))
		if resp.StatusCode != http.StatusUnauthorized || c.Tokens == nil || attempt >= 2 {
			return resp, nil
		}
		challenge := resp.Header.Get("WWW-Authenticate")
		drain(resp)
		c.debugf("%s 401, cycling token (attempt %d)", req.Method, attempt+1)
		rejected := token
		if rejected == "" {
			rejected = "-" // anonymous rejection marker, see TokenProvider
		}
		if token, err = c.token(ctx, rejected, challenge); err != nil {
			return nil, &AuthError{err}
		}
	}
}

// Post sends one client→server JSON-RPC message. Every resulting
// server→client message (single JSON body or each SSE event) is compacted
// and passed to deliver. 401 is resolved via the TokenProvider; other
// failures return *HTTPError or a transport error.
func (c *Client) Post(ctx context.Context, payload []byte, deliver func([]byte)) error {
	resp, err := c.doAuthed(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		c.prepare(req, token)
		c.debugf("POST %s (%d bytes)", c.Endpoint, len(payload))
		return req, nil
	})
	if err != nil {
		return err
	}
	return c.consumePost(resp, deliver)
}

func (c *Client) consumePost(resp *http.Response, deliver func([]byte)) error {
	c.captureSession(resp)

	switch {
	case resp.StatusCode == http.StatusAccepted:
		drain(resp)
		return nil
	case resp.StatusCode/100 != 2:
		return newHTTPError(resp)
	}
	defer resp.Body.Close()

	ct := resp.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "text/event-stream"):
		r := newSSEReader(resp.Body)
		for {
			ev, err := r.Next()
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("reading POST stream: %w", err)
			}
			c.deliverCompact(ev.Data, deliver)
		}
	default: // application/json (or a server being sloppy about Content-Type)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("reading response: %w", err)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return nil // some servers 200 with empty body on notifications
		}
		// An unparseable single-message body must surface as an error so the
		// caller can answer the pending request (bridge synthesizes -32603) —
		// silently dropping it would hang the stdio client.
		if !c.deliverCompact(body, deliver) {
			return fmt.Errorf("upstream sent an invalid JSON body (%d bytes)", len(body))
		}
		return nil
	}
}

// newHTTPError captures up to 64 KB of body into the error and closes it.
func newHTTPError(resp *http.Response) *HTTPError {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return &HTTPError{Status: resp.StatusCode, Body: body}
}

// deliverCompact validates a JSON payload, compacts it if it contains
// newlines (SSE multi-line data — forbidden on the stdio channel), and hands
// it over. Reports false for invalid JSON (logged; SSE callers drop and
// continue, the JSON-body caller turns it into an error).
func (c *Client) deliverCompact(data []byte, deliver func([]byte)) bool {
	if bytes.IndexByte(data, '\n') < 0 && json.Valid(data) {
		deliver(data) // common case: already compact enough for framing
		return true
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, data); err != nil {
		c.debugf("non-JSON server payload (%d bytes): %v", len(data), err)
		return false
	}
	deliver(buf.Bytes())
	return true
}

// Listen opens the server→client GET stream and delivers events until ctx is
// done, reconnecting with Last-Event-ID and exponential backoff (1s→30s cap)
// on stream drops. Returns ErrNoStream if the server answers 405/404, ctx.Err
// on cancellation.
func (c *Client) Listen(ctx context.Context, deliver func([]byte)) error {
	backoff := time.Second
	for {
		err := c.listenOnce(ctx, deliver)
		switch {
		case errors.Is(err, ErrNoStream), errors.Is(err, ErrSessionExpired):
			return err
		case ctx.Err() != nil:
			return ctx.Err()
		}
		if err != nil {
			c.debugf("GET stream: %v, reconnect in %s", err, backoff)
		} else {
			backoff = time.Second // stream worked; only the reconnect is delayed
			c.debugf("GET stream closed by server, reconnect in %s", backoff)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(jitter(backoff)):
		}
		if backoff *= 2; backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
	}
}

func (c *Client) listenOnce(ctx context.Context, deliver func([]byte)) error {
	var hadSession bool
	resp, err := c.doAuthed(ctx, func(token string) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Endpoint, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "text/event-stream")
		c.prepare(req, token)
		hadSession = req.Header.Get("Mcp-Session-Id") != ""
		c.mu.Lock()
		if c.lastEventID != "" {
			req.Header.Set("Last-Event-ID", c.lastEventID)
		}
		c.mu.Unlock()
		return req, nil
	})
	if err != nil {
		return err
	}
	switch {
	case resp.StatusCode == http.StatusMethodNotAllowed:
		drain(resp)
		return ErrNoStream
	case resp.StatusCode == http.StatusNotFound:
		drain(resp)
		if hadSession {
			return ErrSessionExpired
		}
		return ErrNoStream
	case resp.StatusCode/100 != 2:
		return newHTTPError(resp)
	}
	c.captureSession(resp)
	c.debugf("GET stream open")

	r := newSSEReader(resp.Body)
	for {
		ev, err := r.Next()
		if err != nil {
			resp.Body.Close()
			if errors.Is(err, io.EOF) {
				return nil // server closed; caller reconnects
			}
			return err
		}
		if ev.ID != "" {
			c.mu.Lock()
			c.lastEventID = ev.ID
			c.mu.Unlock()
		}
		c.deliverCompact(ev.Data, deliver)
	}
}

// DeleteSession best-effort terminates the session (405 is allowed by spec).
func (c *Client) DeleteSession(ctx context.Context) {
	c.mu.Lock()
	id := c.sessionID
	c.mu.Unlock()
	if id == "" {
		return
	}
	token, err := c.token(ctx, "", "")
	if err != nil {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.Endpoint, nil)
	if err != nil {
		return
	}
	c.prepare(req, token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		c.debugf("DELETE session: %v", err)
		return
	}
	drain(resp)
	c.debugf("DELETE session → %d", resp.StatusCode)
}

func drain(resp *http.Response) {
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10)) //nolint:errcheck // keep-alive drain
	resp.Body.Close()
}

func jitter(d time.Duration) time.Duration {
	// ±25% deterministic-ish jitter is enough to de-sync reconnect storms.
	n := time.Now().UnixNano()
	return d + time.Duration(n%int64(d/2)) - d/4
}
