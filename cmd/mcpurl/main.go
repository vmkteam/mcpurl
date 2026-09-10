// mcpurl bridges stdio MCP clients (Claude Desktop, Cursor, Windsurf) to
// remote Streamable HTTP MCP servers, with OAuth 2.1 PKCE handled locally.
//
// This package is the CLI shell only: flags, dispatch, exit codes, signals.
// The application logic lives in pkg/app.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/vmkteam/mcpurl/pkg/app"
)

const appName = "mcpurl"

// clientHelp is the --client flag help, derived from the one supported list.
var clientHelp = "target MCP client: " + strings.Join(app.Clients(), "|")

var version = "dev" // stamped via -ldflags "-X main.version=…"

// Exit codes (02-cli.md).
const (
	exitOK        = 0
	exitTransport = 1
	exitUsage     = 2
	exitAuth      = 3
)

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage()
		return exitUsage
	}
	switch args[0] {
	case "login":
		return cmdLogin(args[1:])
	case "logout":
		return cmdLogout(args[1:])
	case "token":
		return cmdToken(args[1:])
	case "show":
		return cmdShow(args[1:])
	case "claude-config":
		return cmdClaudeConfig(args[1:])
	case "install":
		return cmdInstall(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "version":
		fmt.Fprintln(os.Stdout, appName, version)
		return exitOK
	case "help", "-h", "--help":
		usage()
		return exitOK
	default:
		return cmdBridge(args)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `mcpurl — stdio ↔ Streamable HTTP MCP bridge with local OAuth 2.1 (PKCE).

Usage:
  mcpurl [flags] <url | @profile>          run the stdio bridge (default)
  mcpurl login  [flags] <url | @profile>   interactive browser PKCE login
  mcpurl logout <url | @profile | --all>   drop stored tokens
  mcpurl token  [flags] <url | @profile>   print access_token (auto-refresh)
  mcpurl show   [name]                     list profiles / show one (no secrets)
  mcpurl claude-config <url | @profile>    print MCP client config snippets
  mcpurl install   [flags] <url | @profile>
                                           write the entry into the MCP client's
                                           config (persists/updates the profile)
  mcpurl uninstall <name | @profile> [--client ...]
                                           remove the entry, its profile and its
                                           stored tokens
  mcpurl version

Profiles: ~/.config/mcpurl/config.toml (MCPURL_CONFIG overrides). The "@" is
optional everywhere — "@mysrv" and "mysrv" are the same target. Run
'mcpurl <cmd> -h' for flags.`)
}

func fail(code int, err error) int {
	fmt.Fprintln(os.Stderr, appName+":", err)
	return code
}

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// stringList is a repeatable string flag ("--header K:V --header K2:V2").
type stringList []string

func (l *stringList) String() string     { return strings.Join(*l, ", ") }
func (l *stringList) Set(v string) error { *l = append(*l, v); return nil }

// commaList splits a "a, b,c" flag value into trimmed items.
type commaList []string

func (l *commaList) String() string { return strings.Join(*l, ",") }
func (l *commaList) Set(v string) error {
	*l = nil
	for _, s := range strings.Split(v, ",") {
		*l = append(*l, strings.TrimSpace(s))
	}
	return nil
}

// newFlagSet binds flags directly into app.Options — no mirror struct.
func newFlagSet(name string, o *app.Options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.ClientID, "client-id", "", "OAuth client_id (overrides profile)")
	fs.Var((*commaList)(&o.Scopes), "scopes", "comma-separated OAuth scopes override")
	fs.IntVar(&o.CallbackPort, "callback-port", 0, "loopback port for the OAuth callback (default 18075)")
	fs.StringVar(&o.Issuer, "issuer", "", "skip RFC 9728 discovery, use this authorization server")
	fs.Var((*stringList)(&o.Headers), "header", "extra HTTP header K:V, repeatable; $VAR expanded")
	fs.StringVar(&o.BearerEnv, "bearer-env", "", "static bearer from env var (MY_<NAME> checked first); disables OAuth")
	fs.BoolVar(&o.NoOAuth, "no-oauth", false, "never attempt OAuth (fail on 401)")
	fs.BoolVar(&o.NoKeychain, "no-keychain", false, "force file token store")
	fs.BoolVar(&o.NoSSE, "no-sse", false, "don't open the GET listening stream")
	fs.BoolVar(&o.AllowHTTP, "allow-http", false, "permit plain http for non-loopback hosts")
	fs.DurationVar(&o.Timeout, "timeout", 10*time.Second, "connect/TLS handshake timeout")
	fs.BoolVar(&o.Verbose, "v", false, "debug log to stderr (Authorization redacted)")
	return fs
}

// parseTarget parses flags allowing the positional target anywhere:
// `mcpurl @p -v` and `mcpurl -v @p` both work with stdlib flag.
func parseTarget(fs *flag.FlagSet, args []string) (string, error) {
	target := ""
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return "", err
		}
		if fs.NArg() == 0 {
			return target, nil
		}
		if target != "" {
			return "", fmt.Errorf("unexpected argument %q", fs.Arg(0))
		}
		target = fs.Arg(0)
		rest = fs.Args()[1:]
	}
}

// setup is the common command prologue: flags, target, app construction.
func setup(name string, args []string) (*app.App, error) {
	var o app.Options
	fs := newFlagSet(name, &o)
	target, err := parseTarget(fs, args)
	if err != nil {
		return nil, err
	}
	if target == "" {
		return nil, fmt.Errorf("usage: %s [flags] <url | @profile>", name)
	}
	o.Target, o.Version = target, version
	return app.New(o, os.Stderr)
}

func cmdBridge(args []string) int {
	a, err := setup(appName, args)
	if err != nil {
		return fail(exitUsage, err)
	}
	ctx, stop := signalCtx()
	defer stop()
	if err := a.Bridge(ctx, os.Stdin, os.Stdout); err != nil {
		if app.IsAuthError(err) {
			return fail(exitAuth, err)
		}
		return fail(exitTransport, err)
	}
	return exitOK
}

func cmdLogin(args []string) int {
	a, err := setup(appName+" login", args)
	if err != nil {
		return fail(exitUsage, err)
	}
	ctx, stop := signalCtx()
	defer stop()
	t, err := a.Login(ctx)
	if errors.Is(err, app.ErrStaticAuth) {
		return fail(exitUsage, err)
	}
	if err != nil {
		return fail(exitAuth, err)
	}
	fmt.Fprintf(os.Stderr, "logged in; access token expires %s\n", t.Expiry.Format(time.RFC3339))
	return exitOK
}

func cmdToken(args []string) int {
	a, err := setup(appName+" token", args)
	if err != nil {
		return fail(exitUsage, err)
	}
	ctx, stop := signalCtx()
	defer stop()
	tok, err := a.AccessToken(ctx)
	if err != nil {
		return fail(exitAuth, err)
	}
	fmt.Fprintln(os.Stdout, tok)
	return exitOK
}

func cmdLogout(args []string) int {
	var o app.Options
	fs := newFlagSet(appName+" logout", &o)
	all := fs.Bool("all", false, "drop tokens for every profile")
	target, err := parseTarget(fs, args)
	if err != nil {
		return fail(exitUsage, err)
	}
	switch {
	case *all:
		a, err := app.New(o, os.Stderr) // no target: config only
		if err != nil {
			return fail(exitUsage, err)
		}
		if err := a.LogoutAll(); err != nil {
			return fail(exitUsage, err)
		}
	case target == "":
		return fail(exitUsage, errors.New("usage: mcpurl logout <url | @profile | --all>"))
	default:
		o.Target = target
		a, err := app.New(o, os.Stderr)
		if err != nil {
			return fail(exitUsage, err)
		}
		if err := a.Logout(); err != nil {
			return fail(exitUsage, err)
		}
	}
	return exitOK
}

func cmdInstall(args []string) int {
	var o app.Options
	fs := newFlagSet(appName+" install", &o)
	client := fs.String("client", "claude-desktop", clientHelp)
	name := fs.String("name", "", "entry/profile name (default: profile name or host)")
	dryRun := fs.Bool("dry-run", false, "print the resulting config without writing")
	target, err := parseTarget(fs, args)
	if err != nil {
		return fail(exitUsage, err)
	}
	if target == "" {
		return fail(exitUsage, errors.New("usage: mcpurl install [flags] <url | @profile>"))
	}
	o.Target, o.Version = target, version
	a, err := app.New(o, os.Stderr)
	if err != nil {
		return fail(exitUsage, err)
	}
	if err := a.Install(os.Stdout, *client, *name, *dryRun); err != nil {
		return fail(exitUsage, err)
	}
	return exitOK
}

func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet(appName+" uninstall", flag.ContinueOnError)
	client := fs.String("client", "claude-desktop", clientHelp)
	name, err := parseTarget(fs, args)
	if err != nil || name == "" {
		return fail(exitUsage, errors.New("usage: mcpurl uninstall <name | @profile> [--client ...]"))
	}
	a, err := app.New(app.Options{}, os.Stderr)
	if err != nil {
		return fail(exitUsage, err)
	}
	if err := a.Uninstall(*client, name); err != nil {
		return fail(exitUsage, err)
	}
	return exitOK
}

func cmdShow(args []string) int {
	a, err := app.New(app.Options{}, os.Stderr)
	if err != nil {
		return fail(exitUsage, err)
	}
	name := ""
	if len(args) > 0 {
		name = args[0]
	}
	if err := a.Show(os.Stdout, name); err != nil {
		return fail(exitUsage, err)
	}
	return exitOK
}

func cmdClaudeConfig(args []string) int {
	fs := flag.NewFlagSet(appName+" claude-config", flag.ContinueOnError)
	name := fs.String("name", "", "server name in the client config (default: profile name or host)")
	target, err := parseTarget(fs, args)
	if err != nil || target == "" {
		return fail(exitUsage, errors.New("usage: mcpurl claude-config <url | @profile> [--name NAME]"))
	}
	a, err := app.New(app.Options{}, os.Stderr)
	if err != nil {
		return fail(exitUsage, err)
	}
	if err := a.ClaudeConfig(os.Stdout, target, *name); err != nil {
		return fail(exitUsage, err)
	}
	return exitOK
}
