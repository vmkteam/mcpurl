# mcpurl

[![CI](https://github.com/vmkteam/mcpurl/actions/workflows/ci.yml/badge.svg)](https://github.com/vmkteam/mcpurl/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/vmkteam/mcpurl.svg)](https://pkg.go.dev/github.com/vmkteam/mcpurl)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A single-binary bridge between **stdio MCP clients** (Claude Desktop, Cursor,
Windsurf) and **remote MCP servers over Streamable HTTP**, with OAuth 2.1
(PKCE) handled locally. Zero runtime dependencies — no Node, no npx.

```
Claude Desktop ── stdio ── mcpurl ── HTTPS ── https://mcp.example.com/mcp
                             │
                             └─ browser PKCE ── Keycloak / authentik / any OAuth 2.1 AS
```

## Why

Claude Desktop's built-in remote connectors reach MCP servers **from
Anthropic's backend** — servers on private/corporate networks are unreachable.
A local stdio bridge is the only path in, and the incumbent (`mcp-remote`)
requires Node, stores tokens in plaintext and has a history of refresh-token
races. mcpurl is a clean-room Go replacement:

- **Single static binary** (darwin/linux/windows), MIT.
- **Tokens live in the OS keychain** (file fallback), never in config files.
- **Refresh-rotation safe**: atomic writes + cross-process file lock; Keycloak
  "Revoke Refresh Token" mode is the design assumption, not an edge case.
  "Both tokens expired" ends in exactly one browser login — never a loop.
- **Zero IdP-specific code**: full RFC 9728 / RFC 8414 / OIDC discovery with
  issuer & resource validation and a PKCE downgrade guard. Keycloak today,
  authentik tomorrow — same binary, different profile.
- **Protocol-version-agnostic passthrough**: JSON-RPC flows through untouched;
  the bridge follows the MCP 2025-06-18 Streamable HTTP transport (SSE
  streams, session re-init on 404, `Last-Event-ID` resume, graceful drain).

## Install

```bash
go install github.com/vmkteam/mcpurl/cmd/mcpurl@latest
# or from a checkout:
make install
```

## Quick start

One command — it persists a profile and writes the Claude Desktop config
entry (with a `.bak` backup, other servers untouched):

```bash
mcpurl install https://mcp.example.com/mcp --client-id mcp-cli --name mysrv
# restart Claude Desktop; the browser opens for login on first use
```

Prefer to log in ahead of time:

```bash
mcpurl login @mysrv     # browser → IdP → tokens in the keychain
mcpurl token @mysrv     # print a live access token (auto-refresh) for curl
```

Undo: `mcpurl uninstall mysrv` (profile and tokens stay; `mcpurl logout
@mysrv` drops the tokens).

> **Claude Code doesn't need a bridge** — it connects directly:
> `claude mcp add --transport http mysrv https://mcp.example.com/mcp`

## Commands

```
mcpurl [flags] <url | @profile>          run the stdio bridge (default command)
mcpurl login  <url | @profile>           interactive browser PKCE login
mcpurl logout <url | @profile | --all>   drop stored tokens
mcpurl token  <url | @profile>           print access_token (auto-refresh)
mcpurl show   [name]                     list profiles / show one (no secrets)
mcpurl claude-config <url | @profile>    print ready-to-paste client config
mcpurl install   <url | @profile> [--client claude-desktop|cursor|windsurf]
                                         write the entry into the client config
mcpurl uninstall <name> [--client ...]   remove a previously installed entry
mcpurl version
```

The bare-URL form works with zero config against any spec-compliant server —
discovery does the rest. A profile only pins what discovery can't provide
(client_id, a non-default callback port, scope overrides).

## Profiles

`~/.config/mcpurl/config.toml` (`MCPURL_CONFIG` overrides the path). No
secrets live here — tokens are in the keychain/token store:

```toml
[profiles.mysrv]
url          = "https://mcp.example.com/mcp"
clientID     = "mcp-cli"
callbackPort = 18075
scopes       = ["openid", "profile", "offline_access"]
# issuer     = "https://auth.example.com/realms/main"  # optional: skip discovery

  [profiles.mysrv.headers]
  # "X-Team" = "$MY_TEAM"                              # $VAR expanded from env
```

Resolution order for every setting: **flag > profile > discovery > default**.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--client-id ID` | — | OAuth client_id (overrides profile) |
| `--scopes "a,b"` | discovery | OAuth scopes override |
| `--callback-port N` | `18075` | Loopback port for `http://127.0.0.1:N/callback`; register it in the IdP |
| `--issuer URL` | — | Skip RFC 9728 discovery, use this authorization server |
| `--header K:V` | — | Extra HTTP header, repeatable; `$VAR` expanded |
| `--bearer-env NAME` | — | Static bearer from env (`MY_<NAME>` checked first); disables OAuth |
| `--no-oauth` | false | Never attempt OAuth (401 is fatal) |
| `--no-keychain` | false | Force the file token store |
| `--no-sse` | false | Don't open the GET listening stream |
| `--allow-http` | false | Permit plain http for non-loopback hosts |
| `--timeout 10s` | `10s` | Connect/TLS timeout (no overall response timeout — tools can be slow) |
| `-v` | false | Debug log to stderr, `Authorization` redacted |

## How auth works

On the first `401` mcpurl discovers the authorization server (RFC 9728
`WWW-Authenticate`/well-known → RFC 8414 / OIDC metadata), validates the
issuer and resource identifiers, refuses PKCE-less servers, and runs the
Authorization Code + PKCE (S256) flow through your browser with the RFC 8707
`resource` parameter. Tokens are stored in the macOS keychain / Secret
Service (files with `0600` elsewhere), keyed by endpoint + client_id.

Refresh is proactive (60 s before expiry) and single-flight across
processes: several bridge instances coordinate via a file lock, always
persisting rotated refresh tokens. If refresh is rejected, mcpurl falls back
to one interactive login — the pending MCP request just waits.

The IdP client must be **public** with PKCE S256 and have
`http://127.0.0.1:<callbackPort>/callback` registered as a redirect URI.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | stdin EOF / clean shutdown |
| 1 | fatal transport error |
| 2 | usage / bad profile |
| 3 | auth failed |

## Troubleshooting

- stdout is exclusively the MCP channel; everything human-readable goes to
  stderr. Claude Desktop keeps it in `~/Library/Logs/Claude/mcp-server-*.log`.
- Add `"-v"` to the client's `args` for a full trace (tokens are redacted).
- `login` fails with "port busy or not registered"? Check the redirect URI in
  the IdP and that nothing else listens on the callback port.
- Manual end-to-end check: `npx @modelcontextprotocol/inspector` with command
  `mcpurl`, args `@mysrv`.

## Development

```bash
make test     # go test -race ./...
make lint     # golangci-lint (config verified in CI)
make build    # ./mcpurl with the version stamped from git
make dist     # darwin arm64/amd64, linux amd64, windows amd64
```

Layout: `cmd/mcpurl` (CLI shell) → `pkg/app` (profiles, wiring, commands) →
`pkg/mcp` (Streamable HTTP client, SSE parser, stdio bridge) + `pkg/oauth`
(discovery, PKCE login, refresh, token storage). `pkg/mcp` and `pkg/oauth`
are independent; the bridge sees auth only as a `TokenProvider` interface.

## License

[MIT](LICENSE)
