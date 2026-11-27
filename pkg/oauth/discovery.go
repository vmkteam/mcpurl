// Package oauth implements the MCP authorization client side: RFC 9728 /
// 8414 / OIDC discovery, browser PKCE login, single-flight token refresh
// with rotation handling, the client_credentials grant for service accounts,
// and token storage (keychain / files). IdP-agnostic: Keycloak and authentik
// are just discovery results. The one IdP-specific shape — authentik's
// service-account password in the client_credentials form — is confined to
// credentials.go.
package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/vmkteam/mcpurl/pkg/redact"
)

const (
	methodS256    = "S256"           // the only PKCE method mcpurl speaks
	scopeOpenID   = "openid"         // OIDC default scope
	scopeProfile  = "profile"        // OIDC default scope
	scopeOffline  = "offline_access" // OIDC Core §11: no refresh token without it
	paramResource = "resource"       // RFC 8707 resource indicator
	paramScope    = "scope"          // challenge parameter and token-response field

	// Well-known document names (RFC 8414 / RFC 9728 / OIDC Discovery).
	wkOAuthAS = "oauth-authorization-server"
	wkOIDC    = "openid-configuration"
	wkPRM     = "oauth-protected-resource"
)

// ASMetadata is the subset of RFC 8414 / OIDC discovery we need.
type ASMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint"` // RFC 7591; "" = no DCR
	ScopesSupported               []string `json:"scopes_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	// FromOIDC records that the document came from an openid-configuration
	// probe — enables the pragmatic default scopes (04-oauth.md).
	FromOIDC bool `json:"-"`
}

type prMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
}

// discovery is the cached result of the full chain.
type discovery struct {
	AS        *ASMetadata
	PRMScopes []string
}

// Canonicalize produces the RFC 8707 resource value for an MCP endpoint:
// lowercase scheme/host, no fragment, no trailing slash.
func Canonicalize(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("bad endpoint URL %q: %w", raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("endpoint must be an absolute http(s) URL, got %q", raw)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.Path = strings.TrimSuffix(u.Path, "/")
	return u.String(), nil
}

// IsLoopbackHost reports whether host is localhost or a loopback IP — the
// shared predicate behind every plain-http allowance in mcpurl.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// requireHTTPS rejects plain-http URLs for non-loopback hosts. The MCP
// server controls all discovered URLs — treat them as untrusted input.
func requireHTTPS(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" || IsLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("discovered URL %q is not https", raw)
}

var challengeParamRe = regexp.MustCompile(`(\w+)="([^"]*)"`)

// bearerChallenge is the parsed subset of a WWW-Authenticate: Bearer header:
// discovery and scope resolution need the first two, the retry ladder and the
// operator need the RFC 6750 §3.1 error pair.
type bearerChallenge struct {
	ResourceMetadata string // RFC 9728
	Scope            string
	Error            string
	ErrorDescription string
}

// detail renders the error pair for a message ("" when the server named no
// error). The challenge is what a server tells an unauthenticated client, so
// nothing in it is secret by design — but error_description is free text, and
// a gateway that pastes the rejected token into it would otherwise put that
// token in an error the MCP client displays.
func (c bearerChallenge) detail() string {
	switch {
	case c.Error == "":
		return ""
	case c.ErrorDescription == "":
		return c.Error
	default:
		return redact.Tokens(c.Error + ": " + c.ErrorDescription)
	}
}

// staleToken reports that the resource server called the credential expired
// rather than foreign or malformed. Expiry is the one rejection a new token
// can still fix (clock skew, an early-issued token), so it keeps the browser
// rung of the ladder available — see Flow.obtain.
func (c bearerChallenge) staleToken() bool {
	return c.Error == "invalid_token" &&
		strings.Contains(strings.ToLower(c.ErrorDescription), "expir")
}

// parseChallenge extracts the parameters mcpurl acts on from a
// WWW-Authenticate: Bearer ... header value.
func parseChallenge(h string) bearerChallenge {
	var c bearerChallenge
	for _, m := range challengeParamRe.FindAllStringSubmatch(h, -1) {
		switch m[1] {
		case "resource_metadata":
			c.ResourceMetadata = m[2]
		case paramScope:
			c.Scope = m[2]
		case "error":
			c.Error = m[2]
		case "error_description":
			c.ErrorDescription = m[2]
		}
	}
	return c
}

func (f *Flow) fetchJSON(ctx context.Context, rawURL string, out any) error {
	if err := requireHTTPS(rawURL); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := f.httpc().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		drainBody(resp)
		return fmt.Errorf("GET %s: HTTP %d", rawURL, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// sameIssuer compares issuer identifiers ignoring a single trailing slash —
// the one equality rule for the RFC 8414 mix-up defense and the pinned
// issuer of the client_credentials grant.
func sameIssuer(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

// wellKnown inserts /.well-known/<suffix> between host and path
// (RFC 8414 §3 path insertion; works as the plain root URL for empty path).
func wellKnown(origin *url.URL, suffix, path string) string {
	u := *origin
	u.Path = "/.well-known/" + suffix + path
	u.RawQuery, u.Fragment = "", ""
	return u.String()
}

// discoverPRM runs step 1 of the chain: Protected Resource Metadata.
// Returns the authorization server issuer plus PRM scopes.
func (f *Flow) discoverPRM(ctx context.Context, canonical, challenge string) (issuer string, scopes []string, err error) {
	endpoint, _ := url.Parse(canonical)
	metaURL := parseChallenge(challenge).ResourceMetadata

	candidates := []string{}
	if metaURL != "" {
		candidates = append(candidates, metaURL)
	}
	if endpoint.Path != "" {
		candidates = append(candidates, wellKnown(endpoint, wkPRM, endpoint.Path))
	}
	candidates = append(candidates, wellKnown(endpoint, wkPRM, ""))

	var lastErr error
	for _, c := range candidates {
		var prm prMetadata
		if err := f.fetchJSON(ctx, c, &prm); err != nil {
			lastErr = err
			continue
		}
		// RFC 9728 MUST: the document's resource equals our canonical URL.
		res, err := Canonicalize(prm.Resource)
		if err != nil || res != canonical {
			lastErr = fmt.Errorf("PRM at %s declares resource %q, want %q", c, prm.Resource, canonical)
			f.debugf("%v", lastErr)
			continue
		}
		if len(prm.AuthorizationServers) == 0 {
			lastErr = fmt.Errorf("PRM at %s lists no authorization_servers", c)
			continue
		}
		f.debugf("PRM found at %s, AS: %s", c, prm.AuthorizationServers[0])
		return prm.AuthorizationServers[0], prm.ScopesSupported, nil
	}
	return "", nil, fmt.Errorf("protected resource metadata not found for %s: %w", canonical, lastErr)
}

// discoverAS runs step 2: AS metadata probes in spec order, with issuer
// validation and the PKCE guard.
func (f *Flow) discoverAS(ctx context.Context, issuer string) (*ASMetadata, error) {
	iss, err := url.Parse(strings.TrimSuffix(issuer, "/"))
	if err != nil || iss.Host == "" {
		return nil, fmt.Errorf("bad issuer %q", issuer)
	}

	type probe struct {
		url  string
		oidc bool
	}
	var probes []probe
	if iss.Path != "" {
		probes = []probe{
			{wellKnown(iss, wkOAuthAS, iss.Path), false},
			{wellKnown(iss, wkOIDC, iss.Path), true},
			{iss.String() + "/.well-known/" + wkOIDC, true}, // OIDC path append
		}
	} else {
		probes = []probe{
			{wellKnown(iss, wkOAuthAS, ""), false},
			{wellKnown(iss, wkOIDC, ""), true},
		}
	}

	var lastErr error
	for _, p := range probes {
		var md ASMetadata
		if err := f.fetchJSON(ctx, p.url, &md); err != nil {
			lastErr = err
			continue
		}
		// RFC 8414 §3.3 MUST: metadata issuer == requested issuer (mix-up
		// defense). Compare ignoring a single trailing slash.
		if !sameIssuer(md.Issuer, issuer) {
			lastErr = fmt.Errorf("AS metadata at %s declares issuer %q, want %q", p.url, md.Issuer, issuer)
			f.debugf("%v", lastErr)
			continue
		}
		// The client_credentials grant talks to the token endpoint alone: an
		// AS serving only machine clients may publish nothing else.
		browser := f.Credentials == nil
		if md.TokenEndpoint == "" || browser && md.AuthorizationEndpoint == "" {
			lastErr = fmt.Errorf("AS metadata at %s lacks endpoints", p.url)
			continue
		}
		if md.AuthorizationEndpoint != "" {
			if err := requireHTTPS(md.AuthorizationEndpoint); err != nil {
				return nil, err
			}
		}
		if err := requireHTTPS(md.TokenEndpoint); err != nil {
			return nil, err
		}
		// PKCE guard: absent code_challenge_methods_supported means the AS
		// does not support PKCE (RFC 8414) — refuse, no silent downgrade.
		// Only the browser flow has an authorization code to protect.
		if browser && !slices.Contains(md.CodeChallengeMethodsSupported, methodS256) {
			return nil, fmt.Errorf("authorization server %s does not advertise PKCE S256 (code_challenge_methods_supported=%v) — refusing", issuer, md.CodeChallengeMethodsSupported)
		}
		md.FromOIDC = p.oidc
		f.debugf("AS metadata found at %s", p.url)
		return &md, nil
	}
	return nil, fmt.Errorf("authorization server metadata not found for %s: %w", issuer, lastErr)
}

// discover runs the full chain (with caching) and resolves scopes.
func (f *Flow) discover(ctx context.Context, challenge string) (*discovery, error) {
	f.discoMu.Lock()
	defer f.discoMu.Unlock()
	if f.disco != nil {
		return f.disco, nil
	}

	canonical, err := Canonicalize(f.Endpoint)
	if err != nil {
		return nil, err
	}

	issuer, prmScopes, err := f.resolveIssuer(ctx, canonical, challenge)
	if err != nil {
		return nil, err
	}
	md, err := f.discoverAS(ctx, issuer)
	if err != nil {
		return nil, err
	}
	f.disco = &discovery{AS: md, PRMScopes: prmScopes}
	return f.disco, nil
}

// resolveIssuer picks the authorization server (step 1 of the chain). For
// the browser flow a configured issuer skips RFC 9728. The client_credentials
// grant needs the issuer configured: its secret goes to whatever this answer
// names, and the PRM document is the MCP server's to write — a compromised
// server must not be able to collect the service account's password. The PRM
// is still read for its scopes, which matter as much as for a login; one that
// names another authorization server is refused, not followed.
func (f *Flow) resolveIssuer(ctx context.Context, canonical, challenge string) (issuer string, scopes []string, err error) {
	if f.Credentials == nil {
		if f.Issuer != "" {
			return f.Issuer, nil, nil
		}
		return f.discoverPRM(ctx, canonical, challenge)
	}
	if f.Issuer == "" {
		return "", nil, errors.New("client_credentials needs a configured issuer: the service account's secret must not go wherever the MCP server's metadata points")
	}
	named, scopes, err := f.discoverPRM(ctx, canonical, challenge)
	switch {
	case err != nil:
		f.debugf("no usable protected resource metadata (%v): using the configured issuer, no PRM scopes", err)
		return f.Issuer, nil, nil
	case !sameIssuer(named, f.Issuer):
		return "", nil, fmt.Errorf("%s names authorization server %s, but the profile pins issuer %s — fix whichever is wrong; the service account's secret goes to the configured issuer only", canonical, named, f.Issuer)
	}
	return f.Issuer, scopes, nil
}

// resolveScopes: flag/profile > WWW-Authenticate scope (authoritative per
// spec) > PRM scopes_supported > pragmatic OIDC default > none; every
// discovery-driven answer then passes through withOffline.
func (f *Flow) resolveScopes(d *discovery, challenge string) []string {
	if len(f.Scopes) > 0 {
		return f.Scopes // explicit override: verbatim, omissions included
	}
	supported := d.AS.ScopesSupported
	if scope := parseChallenge(challenge).Scope; scope != "" {
		return withOffline(supported, strings.Fields(scope))
	}
	if len(d.PRMScopes) > 0 {
		return withOffline(supported, d.PRMScopes)
	}
	if d.AS.FromOIDC {
		return withOffline(supported, []string{scopeOpenID, scopeProfile})
	}
	return nil
}

// withOffline returns scopes plus offline_access when the AS advertises it
// (RFC 8414 scopes_supported) and scopes lack it — without it an OIDC AS
// issues no refresh token, and neither a PRM document nor a 401 challenge is
// obliged to ask for it. Scopes we were TOLD to request pass through
// untouched; the one scope mcpurl adds on its own initiative is the one that
// gets gated, so an AS that never mentions it cannot be handed an
// invalid_scope. Always a fresh slice: the input may be cached discovery
// state, while the result outlives it inside a stored Token.
func withOffline(supported, scopes []string) []string {
	out := slices.Clone(scopes)
	if slices.Contains(scopes, scopeOffline) || !slices.Contains(supported, scopeOffline) {
		return out
	}
	return append(out, scopeOffline)
}
