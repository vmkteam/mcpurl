package oauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"golang.org/x/oauth2"
)

const loginTimeout = 5 * time.Minute

// DefaultCallbackPort is the loopback callback port when none is configured;
// it must be registered as a redirect URI in the IdP (vmkteam asksrv-cli precedent).
const DefaultCallbackPort = 18075

// browserLogin runs Authorization Code + PKCE with a loopback callback
// (ported from vmkteam asksrv-cli). Works while the bridge is live: browser
// pops, the pending MCP request waits until the flow completes.
func (f *Flow) browserLogin(ctx context.Context, d *discovery, scopes []string) (*Token, error) {
	canonical, _, err := f.resourceKey()
	if err != nil {
		return nil, err
	}
	port := f.CallbackPort
	if port == 0 {
		port = DefaultCallbackPort
	}
	cfg := &oauth2.Config{
		ClientID: f.ClientID,
		Endpoint: oauth2.Endpoint{
			AuthURL:  d.AS.AuthorizationEndpoint,
			TokenURL: d.AS.TokenEndpoint,
		},
		RedirectURL: fmt.Sprintf("http://127.0.0.1:%d/callback", port),
		Scopes:      scopes,
	}

	verifier := oauth2.GenerateVerifier()
	state := oauth2.GenerateVerifier()[:24] // ≥16 bytes of entropy
	resource := oauth2.SetAuthURLParam(paramResource, canonical)
	authURL := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), resource)

	var lc net.ListenConfig
	listener, err := lc.Listen(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("listen 127.0.0.1:%d: %w (port busy, or not registered as a redirect URI in the IdP)", port, err)
	}

	type result struct {
		code string
		err  error
	}
	resCh := make(chan result, 1)
	// Non-blocking: only the first callback counts; a duplicate hit (rescan,
	// reopened tab) must not park the handler goroutine forever.
	report := func(r result) {
		select {
		case resCh <- r:
		default:
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if e := q.Get("error"); e != "" {
			report(result{err: fmt.Errorf("authorization failed: %s — %s", e, q.Get("error_description"))})
			http.Error(w, e, http.StatusBadRequest)
			return
		}
		if q.Get("state") != state {
			report(result{err: errors.New("state mismatch — possible CSRF")})
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<html><body style="font-family:sans-serif"><h2>mcpurl: login OK</h2><p>You can close this tab.</p></body></html>`)
		report(result{code: q.Get("code")})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(listener) //nolint:errcheck // Shutdown below reaps it
	defer func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		srv.Shutdown(shutCtx) //nolint:errcheck // best effort
	}()

	f.printf("Opening browser for login: %s", authURL)
	if oerr := openBrowser(ctx, authURL); oerr != nil {
		f.printf("Could not open a browser (%v) — open the URL above manually.", oerr)
	}

	var res result
	select {
	case res = <-resCh:
	case <-time.After(loginTimeout):
		return nil, errors.New("login timed out after 5 minutes")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if res.err != nil {
		return nil, res.err
	}

	tok, err := cfg.Exchange(ctx, res.code, oauth2.VerifierOption(verifier), resource)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %w", err)
	}
	f.printf("Login OK (access token expires %s).", tok.Expiry.Format(time.RFC3339))
	return &Token{
		AccessToken:  tok.AccessToken,
		RefreshToken: tok.RefreshToken,
		Expiry:       tok.Expiry,
		Scopes:       scopes,
	}, nil
}

func openBrowser(ctx context.Context, url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.CommandContext(ctx, "open", url).Start()
	case "linux":
		return exec.CommandContext(ctx, "xdg-open", url).Start()
	case "windows":
		return exec.CommandContext(ctx, "rundll32", "url.dll,FileProtocolHandler", url).Start()
	}
	return errors.New("unsupported platform")
}
