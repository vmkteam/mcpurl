package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
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

const (
	initReq   = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`
	initedMsg = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
)

// fakeMCP is a stateful Streamable HTTP MCP server for bridge tests.
type fakeMCP struct {
	mu        sync.Mutex
	sessions  map[string]bool
	seq       int
	order     []string // methods in arrival order
	initCount atomic.Int32

	invalidateAfter int32        // >0: kill the session after N non-init POSTs
	posts           atomic.Int32 // non-init POST counter
	fail401Once     atomic.Bool
	fail500         atomic.Bool
	getMessages     []string // pushed over the GET stream
}

func newFakeMCP() *fakeMCP { return &fakeMCP{sessions: map[string]bool{}} }

func (f *fakeMCP) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			f.post(w, r)
		case http.MethodGet:
			f.get(w, r)
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})
}

func (f *fakeMCP) post(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var msg struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	json.Unmarshal(body, &msg)
	f.mu.Lock()
	f.order = append(f.order, msg.Method)
	f.mu.Unlock()

	if f.fail401Once.CompareAndSwap(true, false) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	if msg.Method == "initialize" {
		f.initCount.Add(1)
		f.mu.Lock()
		f.seq++
		id := fmt.Sprintf("sess-%d", f.seq)
		f.sessions[id] = true
		f.mu.Unlock()
		w.Header().Set("Mcp-Session-Id", id)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"fake","version":"0"}}}`, msg.ID)
		return
	}

	sess := r.Header.Get("Mcp-Session-Id")
	f.mu.Lock()
	alive := f.sessions[sess]
	f.mu.Unlock()
	if !alive {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if msg.Method != "" && msg.ID == nil { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}

	n := f.posts.Add(1)
	if f.invalidateAfter > 0 && n == f.invalidateAfter {
		f.mu.Lock()
		delete(f.sessions, sess)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if f.fail500.Load() {
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"echo":%q}}`, msg.ID, msg.Method)
}

func (f *fakeMCP) get(w http.ResponseWriter, r *http.Request) {
	if len(f.getMessages) == 0 {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fl := w.(http.Flusher)
	for _, m := range f.getMessages {
		fmt.Fprintf(w, "data: %s\n\n", m)
		fl.Flush()
	}
	<-r.Context().Done()
}

type harness struct {
	t     *testing.T
	in    io.WriteCloser
	lines chan string
	done  chan error
}

func newHarness(t *testing.T, url string, tp TokenProvider) *harness {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	b := &Bridge{
		Client:       &Client{Endpoint: url, HTTP: &http.Client{}, Tokens: tp},
		In:           inR,
		Out:          outW,
		DrainTimeout: 2 * time.Second,
		Logf:         t.Logf,
	}
	h := &harness{t: t, in: inW, lines: make(chan string, 64), done: make(chan error, 1)}
	go func() {
		h.done <- b.Run(context.Background())
		outW.Close()
	}()
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 0, 64*1024), 32<<20)
		for sc.Scan() {
			h.lines <- sc.Text()
		}
		close(h.lines)
	}()
	return h
}

func (h *harness) send(line string) {
	h.t.Helper()
	_, err := io.WriteString(h.in, line+"\n")
	require.NoError(h.t, err, "send")
}

func (h *harness) expect(substr string) string {
	h.t.Helper()
	select {
	case l, ok := <-h.lines:
		require.True(h.t, ok, "stdout closed while waiting for %q", substr)
		require.Contains(h.t, l, substr)
		return l
	case <-time.After(5 * time.Second):
		h.t.Fatalf("timeout waiting for %q", substr)
	}
	return ""
}

func (h *harness) handshake() {
	h.t.Helper()
	h.send(initReq)
	h.expect(`"protocolVersion":"2025-06-18"`)
	h.send(initedMsg)
}

func (h *harness) close() {
	h.t.Helper()
	h.in.Close()
	select {
	case err := <-h.done:
		require.NoError(h.t, err, "Run")
	case <-time.After(5 * time.Second):
		h.t.Fatal("Run did not exit on stdin EOF")
	}
}

func TestBridgeEndToEnd(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	h.expect(`"echo":"tools/list"`)
	h.close()
	assert.EqualValues(t, 1, f.initCount.Load(), "initialize posts")
}

// The handshake must be serialized (03-transport.md): a request written to
// stdin right after initialize/initialized must not overtake them on the
// wire — HTTP gives no ordering, only the bridge's serial phase does.
func TestBridgeHandshakeOrdering(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	// One write, three messages — no waiting for responses in between.
	h.send(initReq + "\n" + initedMsg + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	h.expect(`"protocolVersion"`)
	h.expect(`"echo":"tools/list"`)
	h.close()

	f.mu.Lock()
	got := strings.Join(f.order, ",")
	f.mu.Unlock()
	assert.Equal(t, "initialize,notifications/initialized,tools/list", got, "on-the-wire order")
}

func TestBridgeBigLine(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	big := strings.Repeat("x", 10<<20) // 10 MB argument
	h.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"blob":"` + big + `"}}`)
	h.expect(`"echo":"tools/call"`)
	h.close()
}

func TestBridgeSessionReinitAndReplay(t *testing.T) {
	f := newFakeMCP()
	f.invalidateAfter = 2 // second tool call hits a dead session
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	h.expect(`"id":2`)
	h.send(`{"jsonrpc":"2.0","id":3,"method":"tools/call"}`)
	h.expect(`"id":3`) // replayed transparently after re-init
	h.close()
	assert.EqualValues(t, 2, f.initCount.Load(), "initial + re-init")
}

func TestBridgeConcurrent404SingleReinit(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"warmup"}`)
	h.expect(`"id":2`)

	// Kill the session server-side, then fire concurrent requests: all 404,
	// exactly one re-init must happen.
	f.mu.Lock()
	f.sessions = map[string]bool{}
	f.mu.Unlock()
	const n = 8
	for i := range n {
		h.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"m"}`, 10+i))
	}
	for range n {
		h.expect(`"result"`)
	}
	h.close()
	assert.EqualValues(t, 2, f.initCount.Load(), "initial + single re-init")
}

type onceCycler struct{ n atomic.Int32 }

func (p *onceCycler) Token(_ context.Context, rejected, _ string) (string, error) {
	if rejected != "" {
		p.n.Add(1)
	}
	return fmt.Sprintf("tok-%d", p.n.Load()), nil
}

func TestBridge401MidSession(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, &onceCycler{})
	h.handshake()
	f.fail401Once.Store(true)
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	h.expect(`"echo":"tools/list"`) // recovered via token cycle + replay
	h.close()
}

func TestBridgeErrorSynthesis(t *testing.T) {
	f := newFakeMCP()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	f.fail500.Store(true)
	h.send(`{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)
	l := h.expect(`"code":-32603`)
	assert.Contains(t, l, `"id":9`)
	assert.Contains(t, l, "upstream HTTP 500")
	h.close()
}

func TestBridgeGetStreamNotifications(t *testing.T) {
	f := newFakeMCP()
	f.getMessages = []string{`{"jsonrpc":"2.0","method":"notifications/resources/updated"}`}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	h := newHarness(t, srv.URL, nil)
	h.handshake()
	h.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`) // triggers listen start
	var got []string
	for range 2 {
		select {
		case l := <-h.lines:
			got = append(got, l)
		case <-time.After(5 * time.Second):
			t.Fatal("timeout")
		}
	}
	assert.Contains(t, strings.Join(got, "\n"), "resources/updated", "GET-stream notification")
	h.close()
}
