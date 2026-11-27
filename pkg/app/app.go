// Package app is the application layer of mcpurl: profile resolution,
// wiring of the MCP bridge (pkg/mcp) with the OAuth token flow (pkg/oauth),
// and the command implementations. It knows nothing about flags, os.Args,
// process exit codes or signals — that is cmd/mcpurl's job; all input comes
// through Options and injected readers/writers.
package app

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/vmkteam/mcpurl/pkg/mcp"
	"github.com/vmkteam/mcpurl/pkg/oauth"
)

// Options is the parsed CLI input (flag > profile > default resolution
// happens in New).
type Options struct {
	Target       string // "@profile" or a bare URL; "" = no profile resolution
	ClientID     string
	Scopes       []string
	CallbackPort int
	Issuer       string
	Headers      []string // "K:V" pairs, $VAR expanded
	BearerEnv    string
	NoOAuth      bool
	NoKeychain   bool
	NoSSE        bool
	AllowHTTP    bool
	Timeout      time.Duration
	Verbose      bool
	Version      string // build identity, logged on bridge start

	ServiceAccount // client_credentials flags (-grant, -username, -password-file, …)
}

// ErrStaticAuth marks operations that make no sense with static auth
// (--bearer-env / --no-oauth): interactive login has nothing to obtain.
var ErrStaticAuth = errors.New("static auth configured")

// IsAuthError classifies err as an authentication failure (02-cli.md exit
// code 3): a TokenProvider failure, or a 401 that bubbled out of the
// handshake — the latter counts even without a TokenProvider (--no-oauth).
func IsAuthError(err error) bool {
	var ae *mcp.AuthError
	var he *mcp.HTTPError
	return errors.As(err, &ae) || (errors.As(err, &he) && he.Status == http.StatusUnauthorized)
}

// App carries the resolved configuration and wires commands together.
type App struct {
	opts    Options
	cfg     *Config
	prof    Profile
	headers http.Header
	httpc   *http.Client // shared by OAuth and MCP traffic (one conn pool)
	log     *slog.Logger
	logf    func(string, ...any) // debug hook for mcp/oauth; nil unless Verbose
	msg     io.Writer            // human-readable output (stderr in the CLI)
}

// New loads the profile config and, when opts.Target is set, resolves and
// validates the effective profile. msg receives human-readable messages and
// slog text records (debug with Verbose, info/warnings always).
func New(opts Options, msg io.Writer) (*App, error) {
	if msg == nil {
		msg = io.Discard
	}
	cfg, err := Load("")
	if err != nil {
		return nil, err
	}
	level := slog.LevelInfo
	if opts.Verbose {
		level = slog.LevelDebug
	}
	a := &App{opts: opts, cfg: cfg, msg: msg}
	a.log = slog.New(slog.NewTextHandler(msg, &slog.HandlerOptions{Level: level}))
	if opts.Verbose {
		// nil otherwise: the hot-path debug hooks nil-check before calling,
		// which spares a fmt.Sprintf per message when the output is filtered.
		a.logf = func(format string, args ...any) { a.log.Debug(fmt.Sprintf(format, args...)) }
	}
	if opts.Target == "" {
		return a, nil // show / claude-config / logout --all need only the config
	}

	if a.prof, err = resolveProfile(cfg, opts); err != nil {
		return nil, err
	}
	if a.headers, err = buildHeaders(a.prof, opts); err != nil {
		return nil, err
	}
	a.httpc = mcp.DefaultHTTPClient(opts.Timeout)
	return a, nil
}

// resolveProfile applies the flag > profile precedence and validates the
// result: URL scheme and the grant settings (fail fast, not on first use).
// Whether the credentials themselves are there is CheckCredentials' job.
func resolveProfile(cfg *Config, opts Options) (Profile, error) {
	prof, err := cfg.Resolve(opts.Target)
	if err != nil {
		return Profile{}, err
	}
	override(&prof.ClientID, opts.ClientID)
	if len(opts.Scopes) > 0 {
		prof.Scopes = opts.Scopes
	}
	override(&prof.CallbackPort, opts.CallbackPort)
	override(&prof.Issuer, opts.Issuer)
	override(&prof.BearerEnv, opts.BearerEnv)
	sa, flags := &prof.ServiceAccount, opts.ServiceAccount
	override(&sa.Grant, flags.Grant)
	override(&sa.Username, flags.Username)
	override(&sa.PasswordFile, absPath(flags.PasswordFile))
	override(&sa.PasswordEnv, flags.PasswordEnv)
	override(&sa.ClientSecretFile, absPath(flags.ClientSecretFile))
	override(&sa.ClientSecretEnv, flags.ClientSecretEnv)

	if err := checkScheme(prof.URL, opts.AllowHTTP); err != nil {
		return Profile{}, err
	}
	if err := validateGrant(prof, opts.NoOAuth); err != nil {
		return Profile{}, err
	}
	return prof, nil
}

// override applies a setting over the stored value when it was given (is
// not the zero value) — a flag over the profile, a fresh install over the
// stored profile.
func override[T comparable](dst *T, v T) {
	var zero T
	if v != zero {
		*dst = v
	}
}

// absPath pins a path typed on the command line to the directory it was typed
// in: install persists it, and the MCP client runs mcpurl from elsewhere.
func absPath(p string) string {
	if p == "" {
		return ""
	}
	if abs, err := filepath.Abs(p); err == nil {
		return abs
	}
	return p
}

// buildHeaders merges profile headers with option headers ($VAR expanded).
func buildHeaders(prof Profile, opts Options) (http.Header, error) {
	h := http.Header{}
	for k, v := range ExpandHeaders(prof.Headers) {
		h.Set(k, v)
	}
	for _, kv := range opts.Headers {
		k, v, ok := strings.Cut(kv, ":")
		if !ok {
			return nil, fmt.Errorf("bad header %q, want K:V", kv)
		}
		h.Add(strings.TrimSpace(k), os.ExpandEnv(strings.TrimSpace(v)))
	}
	return h, nil
}

// warnf reports operational events that must reach the operator without -v.
func (a *App) warnf(format string, args ...any) {
	a.log.Warn(fmt.Sprintf(format, args...))
}

// staticAuth reports that OAuth is not in play (static bearer or --no-oauth).
func (a *App) staticAuth() bool { return a.prof.BearerEnv != "" || a.opts.NoOAuth }

func checkScheme(raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "http" || allowHTTP || oauth.IsLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refusing plain http for non-loopback host %q (use --allow-http)", u.Hostname())
}

// tokenProvider picks static bearer / none / OAuth per the resolved config.
// BearerEnv presence was validated in New.
func (a *App) tokenProvider() mcp.TokenProvider {
	if a.prof.BearerEnv != "" {
		return mcp.StaticToken(BearerFromEnv(a.prof.BearerEnv))
	}
	if a.opts.NoOAuth {
		return nil
	}
	return a.flow()
}

// store is the token backend for this run (--no-keychain forces files).
func (a *App) store() oauth.Store { return oauth.NewStore(a.opts.NoKeychain) }

func (a *App) flow() *oauth.Flow { return a.flowFor(a.prof, a.store()) }

// flowFor builds the token flow of any profile — logout --all and show walk
// profiles other than the resolved one.
func (a *App) flowFor(p Profile, store oauth.Store) *oauth.Flow {
	return &oauth.Flow{
		Endpoint:     p.URL,
		ClientID:     p.ClientID,
		Scopes:       p.Scopes,
		Issuer:       p.Issuer,
		CallbackPort: p.CallbackPort,
		Credentials:  p.credentials(),
		Store:        store,
		HTTP:         a.httpc,
		Logf:         a.logf,
		Warnf:        a.warnf,
		Msg:          a.msg,
	}
}
