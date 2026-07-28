package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		in, want string
		wantErr  bool
	}{
		{"HTTPS://MCP.Acme.EXAMPLE/mcp", "https://mcp.acme.example/mcp", false},
		{"https://x.io/mcp/", "https://x.io/mcp", false},
		{"https://x.io/mcp#frag", "https://x.io/mcp", false},
		{"https://x.io", "https://x.io", false},
		{"ftp://x.io/mcp", "", true},
		{"not a url", "", true},
	}
	for _, tt := range tests {
		got, err := Canonicalize(tt.in)
		if tt.wantErr {
			assert.Error(t, err, tt.in) //nolint:testifylint // table mixes ok/err rows
		} else {
			assert.NoError(t, err, tt.in) //nolint:testifylint // table mixes ok/err rows
		}
		assert.Equal(t, tt.want, got, tt.in)
	}
}

func TestParseChallenge(t *testing.T) {
	rm, scope := parseChallenge(`Bearer resource_metadata="https://x/.well-known/oauth-protected-resource", scope="openid mcp", error="invalid_token"`)
	assert.Equal(t, "https://x/.well-known/oauth-protected-resource", rm)
	assert.Equal(t, "openid mcp", scope)

	rm, scope = parseChallenge("")
	assert.Empty(t, rm)
	assert.Empty(t, scope)
}

// full chain: PRM at path-insertion well-known → Keycloak-style OIDC
// path-append metadata, with issuer+resource validation en route.
func TestDiscoveryChain(t *testing.T) {
	mux := http.NewServeMux()
	var srvURL string
	// MCP endpoint lives at /mcp; PRM path-inserted.
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"resource":              srvURL + "/mcp",
			"authorization_servers": []string{srvURL + "/realms/acme"},
			"scopes_supported":      []string{"openid", "roles"},
		})
	})
	// Keycloak answers only on OIDC path-append.
	mux.HandleFunc("/realms/acme/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           srvURL + "/realms/acme",
			"authorization_endpoint":           srvURL + "/realms/acme/auth",
			"token_endpoint":                   srvURL + "/realms/acme/token",
			"code_challenge_methods_supported": []string{"S256", "plain"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	f := &Flow{Endpoint: srv.URL + "/mcp", ClientID: "c", Logf: t.Logf}
	d, err := f.discover(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, srvURL+"/realms/acme/token", d.AS.TokenEndpoint)
	assert.True(t, d.AS.FromOIDC)

	assert.Equal(t, []string{"openid", "roles"}, f.resolveScopes(d, ""),
		"PRM scopes must win absent a challenge")
	assert.Equal(t, []string{"mcp:tools"}, f.resolveScopes(d, `Bearer scope="mcp:tools"`),
		"challenge scope must be authoritative")
}

func TestDiscoveryIssuerMismatchRejected(t *testing.T) {
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                           "https://evil.example.com",
			"authorization_endpoint":           srvURL + "/auth",
			"token_endpoint":                   srvURL + "/token",
			"code_challenge_methods_supported": []string{"S256"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	f := &Flow{Endpoint: "https://mcp.example.com/mcp", ClientID: "c", Issuer: srv.URL, Logf: t.Logf}
	_, err := f.discover(context.Background(), "")
	require.Error(t, err, "issuer mismatch must be rejected")
}

func TestDiscoveryNoPKCERefused(t *testing.T) {
	mux := http.NewServeMux()
	var srvURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 srvURL,
			"authorization_endpoint": srvURL + "/auth",
			"token_endpoint":         srvURL + "/token",
			// no code_challenge_methods_supported
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL

	f := &Flow{Endpoint: "https://mcp.example.com/mcp", ClientID: "c", Issuer: srv.URL, Logf: t.Logf}
	_, err := f.discover(context.Background(), "")
	require.ErrorContains(t, err, "PKCE", "PKCE-less AS must be refused")
}

func TestDiscoveryPRMResourceMismatchSkipped(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"resource":              "https://other.example.com/mcp",
			"authorization_servers": []string{"https://as.example.com"},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	f := &Flow{Endpoint: srv.URL + "/mcp", ClientID: "c", Logf: t.Logf}
	_, err := f.discover(context.Background(), "")
	require.Error(t, err, "PRM resource mismatch must not be trusted")
}

func TestRequireHTTPS(t *testing.T) {
	assert.NoError(t, requireHTTPS("http://127.0.0.1:8080/x"), "loopback http must pass")  //nolint:testifylint // value check
	assert.NoError(t, requireHTTPS("http://localhost:8080/x"), "localhost http must pass") //nolint:testifylint // value check
	assert.Error(t, requireHTTPS("http://internal.corp/x"), "non-loopback http must fail")
}
