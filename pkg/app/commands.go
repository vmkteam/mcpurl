package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/vmkteam/mcpurl/pkg/mcp"
	"github.com/vmkteam/mcpurl/pkg/oauth"
)

// Bridge runs the stdio↔HTTP pump until in is exhausted or ctx is canceled.
func (a *App) Bridge(ctx context.Context, in io.Reader, out io.Writer) error {
	a.log.InfoContext(ctx, "starting",
		"app", "mcpurl", "version", a.opts.Version, "endpoint", a.prof.URL)
	client := &mcp.Client{
		Endpoint: a.prof.URL,
		HTTP:     a.httpc,
		Tokens:   a.tokenProvider(),
		Headers:  a.headers,
		Logf:     a.logf,
	}
	b := &mcp.Bridge{
		Client: client,
		In:     in,
		Out:    out,
		Logf:   a.logf,
		Warnf:  a.warnf,
		NoSSE:  a.opts.NoSSE,
	}
	return b.Run(ctx)
}

// Login runs the interactive browser PKCE flow and persists the token.
// With static auth configured it fails with ErrStaticAuth: there is nothing
// a browser flow could obtain for a bearer-env/no-oauth profile.
func (a *App) Login(ctx context.Context) (*oauth.Token, error) {
	if a.staticAuth() {
		return nil, fmt.Errorf("%w: login does not apply", ErrStaticAuth)
	}
	return a.flow().Login(ctx)
}

// AccessToken returns a valid access token (refreshing or logging in as
// needed). With static auth it returns the configured bearer value.
func (a *App) AccessToken(ctx context.Context) (string, error) {
	tp := a.tokenProvider()
	if tp == nil {
		return "", errors.New("no-oauth: no token to print")
	}
	return tp.Token(ctx, "", "")
}

// Logout drops the stored token for the resolved profile.
func (a *App) Logout() error {
	if a.prof.ClientID == "" {
		return errors.New("logout needs a clientID (profile or --client-id) to locate the stored token")
	}
	a.dropTokens(a.store(), a.prof)
	return nil
}

// LogoutAll drops tokens for every configured profile plus file-backend
// leftovers from bare-URL runs; needs no target resolution.
func (a *App) LogoutAll() error {
	store := a.store()
	for _, name := range a.cfg.Names() {
		a.dropTokens(store, a.cfg.Profiles[name])
	}
	oauth.WipeFiles() //nolint:errcheck // best-effort cleanup
	return nil
}

// dropTokens deletes the stored token for p. The deletion is unconditional
// (an unreadable leftover must go too), but nothing is reported when there was
// nothing stored — "dropped tokens" for an empty store reads as a lie.
func (a *App) dropTokens(store oauth.Store, p Profile) {
	if p.URL == "" || p.ClientID == "" {
		return
	}
	key, err := oauth.KeyFor(p.URL, p.ClientID)
	if err != nil {
		return
	}
	// Load first only to decide whether to report: it costs one os.ReadFile
	// for the "nothing stored" case (both backends answer ErrNotFound before
	// touching the keyring), and Delete must stay a no-op either way.
	_, loadErr := store.Load(key)
	if err := store.Delete(key); err != nil {
		a.warnf("logout %s: %v", p.Name, err)
		return
	}
	if !errors.Is(loadErr, oauth.ErrNotFound) {
		fmt.Fprintf(a.msg, "dropped tokens for %s\n", p.URL)
	}
}

// Show writes the profile list (name == "") or one profile without secrets.
func (a *App) Show(w io.Writer, name string) error {
	if name == "" {
		if len(a.cfg.Profiles) == 0 {
			fmt.Fprintf(w, "no profiles in %s\n", a.cfg.Path)
			return nil
		}
		for _, n := range a.cfg.Names() {
			fmt.Fprintf(w, "@%-20s %s\n", n, a.cfg.Profiles[n].URL)
		}
		return nil
	}
	p, err := a.cfg.Get(name)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "profile:      @%s\nurl:          %s\n", p.Name, p.URL)
	if p.ClientID != "" {
		fmt.Fprintf(w, "clientID:     %s\n", p.ClientID)
	}
	if p.Issuer != "" {
		fmt.Fprintf(w, "issuer:       %s\n", p.Issuer)
	}
	if p.CallbackPort != 0 {
		fmt.Fprintf(w, "callbackPort: %d\n", p.CallbackPort)
	}
	if len(p.Scopes) > 0 {
		fmt.Fprintf(w, "scopes:       %s\n", strings.Join(p.Scopes, ", "))
	}
	if p.BearerEnv != "" {
		fmt.Fprintf(w, "bearerEnv:    %s (value not shown)\n", p.BearerEnv)
	}
	if len(p.Headers) > 0 {
		// Keys only — values may embed env secrets.
		fmt.Fprintf(w, "headers:      %s\n", strings.Join(slices.Sorted(maps.Keys(p.Headers)), ", "))
	}
	return nil
}

// ClaudeConfig writes ready-to-paste MCP client config snippets for target.
// It deliberately skips scheme/auth validation — it only renders config.
func (a *App) ClaudeConfig(w io.Writer, target, name string) error {
	prof, err := a.cfg.Resolve(target)
	if err != nil {
		return err
	}
	if name == "" {
		name = prof.Name
	}
	if name == "" {
		name = hostLabel(prof.URL) // same default install uses
	}
	// The snippet is config, not shorthand: spell the profile reference the
	// way install writes it, "@" included, whichever form was typed.
	arg := target
	if prof.Name != "" {
		arg = "@" + prof.Name
	}
	fmt.Fprintf(w, `# Claude Desktop / Cursor / Windsurf (stdio bridge):
{
  "mcpServers": {
    %q: {
      "command": "mcpurl",
      "args": [%q]
    }
  }
}
# Claude Code (no bridge needed — connects directly):
#   claude mcp add --transport http %s %s
`, name, arg, name, prof.URL)
	return nil
}
