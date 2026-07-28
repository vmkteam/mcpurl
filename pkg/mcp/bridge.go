// Package mcp is the MCP transport of mcpurl: the Streamable HTTP client
// (client.go, sse.go) and the stdio Bridge pumping JSON-RPC lines between an
// MCP client and the remote server. It is protocol-version-agnostic: the
// only JSON it reads is the handshake messages' method/params (routing), the
// initialize result's protocolVersion, and — on error paths only — a failed
// message's id for -32603 synthesis.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Bridge wires stdin/stdout to a Client.
type Bridge struct {
	Client       *Client
	In           io.Reader
	Out          io.Writer
	Logf         func(format string, args ...any) // debug (-v); nil = silent
	Warnf        func(format string, args ...any) // rare operational events; nil = Logf
	NoSSE        bool
	DrainTimeout time.Duration // wait for in-flight requests on shutdown

	out   *bufio.Writer
	outMu sync.Mutex

	// Shared between the Run loop and concurrent send/reinit goroutines.
	handshakeMu    sync.Mutex
	initReq        []byte // cached raw initialize request
	initNote       []byte // cached raw notifications/initialized
	reqProtocolVer string // protocolVersion the client asked for (fallback)
	gen            uint64 // re-init generation (concurrent 404 → one re-init)
	sessioned      bool   // server assigned a session at least once

	// Serial-phase progress, touched only by the Run goroutine — no mutex.
	initDone bool // initialize response received
	noteDone bool // notifications/initialized accepted

	wg sync.WaitGroup
}

type rpcMeta struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method"`
	Params struct {
		ProtocolVersion string `json:"protocolVersion"`
	} `json:"params"`
}

func (b *Bridge) logf(format string, args ...any) {
	if b.Logf != nil {
		b.Logf(format, args...)
	}
}

// warnf reports events an operator needs even without -v: session re-inits,
// failed replays, drain timeouts.
func (b *Bridge) warnf(format string, args ...any) {
	if b.Warnf != nil {
		b.Warnf(format, args...)
		return
	}
	b.logf(format, args...)
}

// Run pumps messages until stdin EOF or ctx cancellation. The returned error
// is nil on clean shutdown; *AuthError means exit code 3.
func (b *Bridge) Run(ctx context.Context) error {
	if b.DrainTimeout == 0 {
		b.DrainTimeout = 5 * time.Second
	}
	b.out = bufio.NewWriter(b.Out)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	lines, readErr := b.readLines(ctx)

	// Serial phase: preserve on-the-wire ordering until the server has both
	// the initialize response delivered and the initialized notification
	// accepted; only then go concurrent (03-transport.md).
	handshakeDone := false
loop:
	for {
		var line []byte
		select {
		case l, ok := <-lines:
			if !ok {
				break loop
			}
			line = l
		case <-ctx.Done():
			break loop
		}

		if handshakeDone {
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()
				b.send(ctx, line)
			}()
			continue
		}
		done, err := b.serialPhase(ctx, line)
		if err != nil {
			return err
		}
		if done {
			handshakeDone = true
			b.startListening(ctx)
		}
	}

	b.drainInFlight()
	cancel()
	delCtx, delCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer delCancel()
	b.Client.DeleteSession(delCtx)

	select {
	case err := <-readErr:
		return fmt.Errorf("reading stdin: %w", err)
	default:
		return nil
	}
}

// readLines pumps stdin lines into a channel; a read failure other than EOF
// lands in the error channel.
func (b *Bridge) readLines(ctx context.Context) (<-chan []byte, <-chan error) {
	lines := make(chan []byte, 8) // decouple stdin reads from dispatch
	readErr := make(chan error, 1)
	go func() {
		defer close(lines)
		r := bufio.NewReaderSize(b.In, 64*1024)
		for {
			line, err := readLine(r)
			if len(line) > 0 {
				select {
				case lines <- line:
				case <-ctx.Done():
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					readErr <- err
				}
				return
			}
		}
	}()
	return lines, readErr
}

// serialPhase processes one pre-handshake message and reports whether the
// handshake is now complete.
func (b *Bridge) serialPhase(ctx context.Context, line []byte) (done bool, err error) {
	var meta rpcMeta
	json.Unmarshal(line, &meta) //nolint:errcheck // non-object lines route via default
	switch meta.Method {
	case "initialize":
		if err := b.handleInitialize(ctx, line, meta.Params.ProtocolVersion); err != nil {
			return false, err
		}
		b.initDone = true
	case "notifications/initialized":
		b.handshakeMu.Lock()
		b.initNote = line
		b.handshakeMu.Unlock()
		if err := b.Client.Post(ctx, line, b.writeOut); err != nil {
			b.logf("initialized notification failed: %v", err)
		}
		b.noteDone = true
	default:
		b.send(ctx, line)
	}
	return b.initDone && b.noteDone, nil
}

// drainInFlight waits for concurrent sends, bounded by DrainTimeout.
func (b *Bridge) drainInFlight() {
	done := make(chan struct{})
	go func() { b.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(b.DrainTimeout):
		b.warnf("drain timeout, abandoning in-flight requests")
	}
}

func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadBytes('\n')
	return bytes.TrimSpace(line), err
}

// handleInitialize caches the raw request for later re-init, forwards it,
// and captures the negotiated protocol version from the response
// (protocolVer — the version the client asked for — is the fallback).
func (b *Bridge) handleInitialize(ctx context.Context, line []byte, protocolVer string) error {
	b.handshakeMu.Lock()
	b.initReq = line
	b.reqProtocolVer = protocolVer
	b.handshakeMu.Unlock()

	err := b.Client.Post(ctx, line, func(msg []byte) {
		b.setProtocolVersion(msg, protocolVer)
		b.writeOut(msg)
	})
	if err != nil {
		var ae *AuthError
		if errors.As(err, &ae) {
			return err // exit 3: auth is required and unobtainable
		}
		b.logf("initialize failed: %v", err)
		b.synthesizeError(line, err)
		return fmt.Errorf("initialize: %w", err)
	}
	b.handshakeMu.Lock()
	b.sessioned = b.Client.session() != ""
	b.handshakeMu.Unlock()
	return nil
}

// setProtocolVersion extracts result.protocolVersion from a delivered
// message (the initialize response); falls back to the requested version.
func (b *Bridge) setProtocolVersion(msg []byte, fallback string) {
	var resp struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
		} `json:"result"`
	}
	v := ""
	if err := json.Unmarshal(msg, &resp); err == nil {
		v = resp.Result.ProtocolVersion
	}
	if v == "" {
		v = fallback
	}
	if v != "" {
		b.Client.setProtocolVersion(v)
	}
}

// send POSTs one message, handling 404 re-init + single replay and error
// synthesis for requests. The message is parsed only on the error path.
func (b *Bridge) send(ctx context.Context, msg []byte) {
	gen := b.generation()
	err := b.Client.Post(ctx, msg, b.writeOut)
	if err == nil {
		return
	}

	var he *HTTPError
	if errors.As(err, &he) && he.Status == 404 && b.everSessioned() {
		if rerr := b.reinit(ctx, gen); rerr != nil {
			b.warnf("session re-init failed: %v", rerr)
			b.synthesizeError(msg, err)
			return
		}
		if err = b.Client.Post(ctx, msg, b.writeOut); err == nil {
			return
		}
		b.warnf("replay after re-init failed: %v", err)
	}

	b.logf("POST failed: %v", err)
	if errors.As(err, &he) && len(he.Body) > 0 {
		b.logf("upstream body: %s", he.Body[:min(len(he.Body), 2048)])
	}
	b.synthesizeError(msg, err)
}

func (b *Bridge) generation() uint64 {
	b.handshakeMu.Lock()
	defer b.handshakeMu.Unlock()
	return b.gen
}

// everSessioned reports whether the server assigned a session at least once.
// It deliberately does NOT look at the current session id: during a re-init
// the id is temporarily empty, and concurrent 404 handlers must still route
// into reinit (the generation check dedups the work).
func (b *Bridge) everSessioned() bool {
	b.handshakeMu.Lock()
	defer b.handshakeMu.Unlock()
	return b.sessioned
}

// reinit re-establishes a server session from the cached handshake. gen is
// the generation observed before the failed request: concurrent 404s all call
// in, but only the first with a current gen re-inits — the rest just replay
// against the fresh session.
func (b *Bridge) reinit(ctx context.Context, gen uint64) error {
	b.handshakeMu.Lock()
	defer b.handshakeMu.Unlock()
	if b.gen != gen {
		return nil // someone already re-initialized after our request started
	}
	old := b.Client.session()

	b.Client.clearSession()
	if len(b.initReq) == 0 {
		return errors.New("no cached initialize request")
	}
	// The internal initialize response must NOT reach stdout (duplicate id);
	// only its protocolVersion and session header are consumed.
	fallback := b.reqProtocolVer
	err := b.Client.Post(ctx, b.initReq, func(msg []byte) {
		b.setProtocolVersion(msg, fallback)
	})
	if err != nil {
		return err
	}
	if len(b.initNote) > 0 {
		if err := b.Client.Post(ctx, b.initNote, func([]byte) {}); err != nil {
			b.logf("re-init: initialized notification failed: %v", err)
		}
	}
	b.gen++
	b.warnf("session re-initialized: %s → %s", old, b.Client.session())
	return nil
}

// startListening opens the server→client GET stream (03-transport.md).
func (b *Bridge) startListening(ctx context.Context) {
	if b.NoSSE {
		return
	}
	go func() {
		for {
			gen := b.generation()
			err := b.Client.Listen(ctx, b.writeOut)
			switch {
			case errors.Is(err, ErrNoStream):
				b.logf("server offers no listening stream")
				return
			case errors.Is(err, ErrSessionExpired):
				if rerr := b.reinit(ctx, gen); rerr != nil {
					b.warnf("listening stream: re-init failed: %v", rerr)
					return
				}
				continue
			default:
				if ctx.Err() != nil {
					return
				}
				b.logf("listening stream stopped: %v", err)
				return
			}
		}
	}()
}

func (b *Bridge) writeOut(msg []byte) {
	b.outMu.Lock()
	defer b.outMu.Unlock()
	b.out.Write(msg)
	b.out.WriteByte('\n')
	if err := b.out.Flush(); err != nil {
		b.logf("stdout write failed: %v", err)
	}
}

// synthesizeError answers a failed request with -32603; notifications and
// client→server responses have nothing to answer, only logging.
func (b *Bridge) synthesizeError(msg []byte, cause error) {
	var meta rpcMeta
	if json.Unmarshal(msg, &meta) != nil {
		return
	}
	isRequest := meta.Method != "" && len(meta.ID) > 0 && !bytes.Equal(meta.ID, []byte("null"))
	if !isRequest {
		return
	}
	text := "upstream error"
	var he *HTTPError
	if errors.As(cause, &he) {
		text = fmt.Sprintf("upstream HTTP %d", he.Status)
	}
	out, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      meta.ID,
		"error":   map[string]any{"code": -32603, "message": text},
	})
	if err != nil {
		return
	}
	b.writeOut(out)
}
