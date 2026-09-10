package mcp

import (
	"context"
	"errors"
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

func newTestClient(url string, tp TokenProvider) *Client {
	return &Client{Endpoint: url, HTTP: &http.Client{}, Tokens: tp}
}

// logCapture stands in for the CLI's -v hook.
type logCapture struct {
	mu    sync.Mutex
	lines []string
}

func (l *logCapture) logf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(format, args...))
}

func (l *logCapture) text() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func (l *logCapture) count(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, line := range l.lines {
		if strings.Contains(line, substr) {
			n++
		}
	}
	return n
}

// authFailure is the authentik-behind-a-resource-server case verbatim: the
// server explains the rejection in the body, and no token can fix it.
const authFailure = `auth: invalid token: oidc: malformed jwt: unexpected signature algorithm "HS256"; expected ["RS256"]`

// always401 serves that failure; requests may be nil when the count is not
// what the test is about.
func always401(requests *atomic.Int32) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if requests != nil {
			requests.Add(1)
		}
		w.Header().Set("WWW-Authenticate",
			`Bearer resource_metadata="https://example.test/.well-known/oauth-protected-resource", error="invalid_token"`)
		http.Error(w, authFailure, http.StatusUnauthorized)
	}
}

func TestPostResponseModes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("mode") {
		case "accepted":
			w.WriteHeader(http.StatusAccepted)
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("{\n  \"jsonrpc\": \"2.0\",\n  \"id\": 1,\n  \"result\": {}\n}"))
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			w.Write([]byte(": hello\n\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"note\"}\n\ndata: {\"jsonrpc\":\ndata: \"2.0\",\"id\":1,\"result\":{}}\n\n"))
		}
	}))
	defer srv.Close()

	tests := []struct {
		mode string
		want []string
	}{
		{"accepted", nil},
		{"json", []string{`{"jsonrpc":"2.0","id":1,"result":{}}`}},
		{"sse", []string{`{"jsonrpc":"2.0","method":"note"}`, `{"jsonrpc":"2.0","id":1,"result":{}}`}},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			c := newTestClient(srv.URL+"/?mode="+tt.mode, nil)
			var got []string
			err := c.Post(context.Background(), []byte(`{}`), func(b []byte) { got = append(got, string(b)) })
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// cyclingProvider escalates stored → refreshed → give up, like oauth.Flow
// does: stored is what the "store" holds, and the refreshed token derives
// from it.
type cyclingProvider struct {
	stored string
	calls  atomic.Int32
}

func (p *cyclingProvider) Token(_ context.Context, rejected, _ string) (string, error) {
	p.calls.Add(1)
	switch rejected {
	case "":
		return p.stored, nil
	case p.stored:
		return p.stored + "-refreshed", nil
	default:
		return "", errors.New("server rejects freshly issued tokens; giving up")
	}
}

func TestPost401Cycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer stale-refreshed" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, &cyclingProvider{stored: "stale"})
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil),
		"expected recovery via token cycle")
}

func TestPost401Fatal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, StaticToken("key"))
	require.Error(t, c.Post(context.Background(), []byte(`{}`), nil))
}

// The server already wrote the diagnosis; -v must show it for EVERY 401 of
// the cycle and the caller must receive it (02-401-body-discarded.md).
func TestPost401SurfacesBodyAndChallenge(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(always401(&requests))
	defer srv.Close()

	var log logCapture
	c := newTestClient(srv.URL, &cyclingProvider{stored: "stale"})
	c.Logf = log.logf

	err := c.Post(context.Background(), []byte(`{}`), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "upstream HTTP 401")
	assert.Contains(t, err.Error(), `unexpected signature algorithm "HS256"`,
		"the server's own explanation must reach the caller")

	assert.EqualValues(t, 2, requests.Load(), "stale, fresh, then the provider gave up")
	assert.Equal(t, 2, log.count(`unexpected signature algorithm "HS256"`),
		"every 401 body, not just the last one")
	assert.Contains(t, log.text(), `error="invalid_token"`, "WWW-Authenticate must be visible")
}

// A provider that hands back the token the server just rejected has nothing
// left to offer: replaying it would only fetch the same 401.
func TestPost401ProviderRepeatsToken(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(always401(&requests))
	defer srv.Close()

	c := newTestClient(srv.URL, &stubbornProvider{})
	err := c.Post(context.Background(), []byte(`{}`), nil)
	var he *HTTPError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, http.StatusUnauthorized, he.Status)
	assert.Contains(t, he.Error(), "malformed jwt", "the 401 body must survive the retry loop")
	assert.EqualValues(t, 1, requests.Load(), "no point replaying a rejected token")
}

// How far the ladder goes is the provider's call: 0.0.2 capped it at two
// tokens, which made oauth.Flow's own give-up rung unreachable.
func TestPost401LadderIsProviderDriven(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-3" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, &countingProvider{})
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
}

// …but a provider that never gives up must not turn a 401 into an endless
// request loop.
func TestPost401LadderBackstop(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(always401(&requests))
	defer srv.Close()

	c := newTestClient(srv.URL, &countingProvider{})
	require.Error(t, c.Post(context.Background(), []byte(`{}`), nil))
	assert.EqualValues(t, maxTokenCycles+1, requests.Load(), "ladder backstop")
}

// A binary body is reported by size and type — stderr and a JSON-RPC string
// are no place for raw bytes.
func TestFailedBinaryBodyIsNotDumped(t *testing.T) {
	blob := []byte{0x00, 0x01, 0x02, 0xff, 0xfe}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write(blob)
	}))
	defer srv.Close()

	var log logCapture
	c := newTestClient(srv.URL, nil)
	c.Logf = log.logf
	err := c.Post(context.Background(), []byte(`{}`), nil)
	require.Error(t, err)

	const placeholder = "<5 bytes of application/octet-stream>"
	assert.Contains(t, log.text(), placeholder)
	assert.NotContains(t, log.text(), string(blob))
	assert.Contains(t, err.Error(), placeholder)
}

// Gateways quote the credential they refused ("Jwt expired: eyJhbGci…").
// Copying that body into -v output and into the message the MCP client
// renders must not put an access token in a plaintext desktop log — the same
// token is AES-256-GCM encrypted at rest.
func TestEchoedTokenIsRedacted(t *testing.T) {
	const jwt = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		presented := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description="Jwt expired: %s"`, presented))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprintf(w, `{"error":"invalid_token","error_description":"Jwt expired: %s"}`, presented)
	}))
	defer srv.Close()

	var log logCapture
	c := newTestClient(srv.URL, &cyclingProvider{stored: jwt})
	c.Logf = log.logf
	err := c.Post(context.Background(), []byte(`{}`), nil)
	require.Error(t, err)

	assert.NotContains(t, log.text(), jwt, "-v leaked the token the server echoed")
	assert.NotContains(t, err.Error(), jwt, "the error text leaks it to the MCP client")
	assert.NotContains(t, log.text(), jwt+"-refreshed", "the refreshed token leaked too")
	assert.Contains(t, log.text(), "[redacted JWT]")
	assert.Contains(t, err.Error(), "Jwt expired", "the diagnosis itself must survive")
}

// The mcp counterpart of oauth.TestNoTokenMaterialInLogs: a full 401 cycle
// must never print the bearer value it sent.
func TestNoTokenMaterialInLogs(t *testing.T) {
	const secret = "s3cr3t-access-token"
	var requests atomic.Int32
	srv := httptest.NewServer(always401(&requests))
	defer srv.Close()

	var log logCapture
	c := newTestClient(srv.URL, &cyclingProvider{stored: secret})
	c.Logf = log.logf
	require.Error(t, c.Post(context.Background(), []byte(`{}`), nil))

	assert.NotEmpty(t, log.text(), "the cycle must have logged something")
	assert.NotContains(t, log.text(), secret, "debug output leaks token material")
}

// stubbornProvider always answers with the same token, rejected or not.
type stubbornProvider struct{}

func (stubbornProvider) Token(context.Context, string, string) (string, error) {
	return "same", nil
}

// countingProvider issues an endless supply of distinct tokens.
type countingProvider struct{ n atomic.Int32 }

func (p *countingProvider) Token(context.Context, string, string) (string, error) {
	return fmt.Sprintf("tok-%d", p.n.Add(1)), nil
}

func TestSessionCaptureAndHeaders(t *testing.T) {
	var sawSession, sawVersion atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSession.Store(r.Header.Get("Mcp-Session-Id"))
		sawVersion.Store(r.Header.Get("Mcp-Protocol-Version"))
		w.Header().Set("Mcp-Session-Id", "sess-1")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
	assert.Equal(t, "sess-1", c.session())

	c.setProtocolVersion("2025-06-18")
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
	assert.Equal(t, "sess-1", sawSession.Load())
	assert.Equal(t, "2025-06-18", sawVersion.Load())
}

func TestInvalidSessionIDIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Mcp-Session-Id", "bad id") // space is outside 0x21–0x7E
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
	assert.Empty(t, c.session(), "invalid session id accepted")
}

// An invalid JSON body on a 200 must surface as an error (the bridge answers
// the pending request with -32603) — silently dropping it would hang the
// stdio client forever.
func TestPostInvalidJSONBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("<html>gateway error</html>"))
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	var delivered int
	err := c.Post(context.Background(), []byte(`{}`), func([]byte) { delivered++ })
	require.Error(t, err)
	assert.Zero(t, delivered)
}

func TestClearSessionResetsEventCursor(t *testing.T) {
	c := newTestClient("https://x", nil)
	c.mu.Lock()
	c.sessionID, c.lastEventID = "s1", "42"
	c.mu.Unlock()
	c.clearSession()
	c.mu.Lock()
	defer c.mu.Unlock()
	assert.Empty(t, c.sessionID)
	assert.Empty(t, c.lastEventID)
}

// The bridge is transparent: rate limits are NOT retried — a 429 must reach
// the caller as an error so the operator learns about it.
func TestPost429Surfaces(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	err := c.Post(context.Background(), []byte(`{}`), nil)
	var he *HTTPError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, http.StatusTooManyRequests, he.Status)
	assert.EqualValues(t, 1, calls.Load(), "no silent retries")
}

func TestPostHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	err := c.Post(context.Background(), []byte(`{}`), nil)
	var he *HTTPError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, http.StatusInternalServerError, he.Status)
}

func TestListenNoStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	require.ErrorIs(t, c.Listen(context.Background(), nil), ErrNoStream)
}

func TestListenSessionExpired(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			w.Header().Set("Mcp-Session-Id", "s1")
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
	require.ErrorIs(t, c.Listen(context.Background(), nil), ErrSessionExpired)
}

func TestListenDeliversAndReconnects(t *testing.T) {
	var conns atomic.Int32
	var lastEventID atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := conns.Add(1)
		lastEventID.Store(r.Header.Get("Last-Event-ID"))
		w.Header().Set("Content-Type", "text/event-stream")
		if n == 1 {
			w.Write([]byte("id: 5\ndata: {\"n\":1}\n\n"))
			return // close → client reconnects
		}
		w.Write([]byte("data: {\"n\":2}\n\n"))
		w.(http.Flusher).Flush()
		// hold the second connection open until the test cancels
		<-r.Context().Done()
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan string, 4)
	go func() {
		c := newTestClient(srv.URL, nil)
		c.Listen(ctx, func(b []byte) { got <- string(b) })
	}()

	expect := func(want string) {
		select {
		case m := <-got:
			assert.Equal(t, want, m)
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for %s", want)
		}
	}
	expect(`{"n":1}`)
	expect(`{"n":2}`)
	assert.Equal(t, "5", lastEventID.Load(), "reconnect Last-Event-ID")
}

func TestDeleteSession(t *testing.T) {
	var deleted atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			w.Header().Set("Mcp-Session-Id", "s1")
			w.WriteHeader(http.StatusAccepted)
		case http.MethodDelete:
			if r.Header.Get("Mcp-Session-Id") == "s1" {
				deleted.Store(true)
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, nil)
	require.NoError(t, c.Post(context.Background(), []byte(`{}`), nil))
	c.DeleteSession(context.Background())
	assert.True(t, deleted.Load(), "DELETE did not carry the session id")
}
