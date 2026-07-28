package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestClient(url string, tp TokenProvider) *Client {
	return &Client{Endpoint: url, HTTP: &http.Client{}, Tokens: tp}
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

// cyclingProvider escalates old → fresh → interactive, like oauth.Flow will.
type cyclingProvider struct{ calls atomic.Int32 }

func (p *cyclingProvider) Token(_ context.Context, rejected, _ string) (string, error) {
	p.calls.Add(1)
	switch rejected {
	case "":
		return "stale", nil
	case "stale":
		return "fresh", nil
	default:
		return "", errors.New("gave up")
	}
}

func TestPost401Cycle(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://x/.well-known/oauth-protected-resource"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	c := newTestClient(srv.URL, &cyclingProvider{})
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
