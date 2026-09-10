// Package redact strips credentials out of server-supplied text before it is
// logged or handed to an MCP client.
//
// The text a server writes is not the server's business alone: gateways quote
// the credential they just refused back at the client
// (`{"error_description":"Jwt expired: eyJhbGci…"}`), and mcpurl now copies
// failed-response bodies into `-v` output and into the JSON-RPC error the
// client renders. Without this filter an access token would land in a
// plaintext desktop-client log — the same token that sits AES-256-GCM
// encrypted in the keychain two directories away.
//
// It lives here because both pkg/mcp (response bodies, challenge headers) and
// pkg/oauth (challenge error_description) need it, and they deliberately do
// not import each other. One rule, one place to audit.
package redact

import (
	"regexp"
	"strings"
)

// jwtRe matches a compact-serialization JWT/JWE: "eyJ" — the base64url of the
// `{"` every JOSE header starts with — plus at least one more dot-separated
// segment. The length floor keeps an ordinary word starting with "eyJ" out.
var jwtRe = regexp.MustCompile(`eyJ[\w-]{8,}(?:\.[\w-]+)+`)

// Tokens replaces every JWT-shaped run in s with a marker, keeping the
// surrounding diagnosis intact — "Jwt expired: [redacted JWT]" still tells
// the user what went wrong.
//
// Shape is all it can match: an opaque bearer token is indistinguishable from
// an id. Treat this as the last line of defence, not a licence to print
// whatever a server sends.
func Tokens(s string) string {
	// ReplaceAllString copies the whole input even with nothing to replace,
	// and the overwhelming majority of server text carries no token at all.
	if !strings.Contains(s, "eyJ") {
		return s
	}
	return jwtRe.ReplaceAllString(s, "[redacted JWT]")
}
