package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vmkteam/mcpurl/pkg/oauth"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeConfig(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	cfg := `
[profiles.acme]
url          = "https://mcp.acme.example/mcp"
clientID     = "acme-cli"
callbackPort = 18075
scopes       = ["openid"]

  [profiles.acme.headers]
  "X-Team" = "team-$MCPURL_TEST_SUFFIX"
`
	require.NoError(t, os.WriteFile(path, []byte(cfg), 0o600))
	t.Setenv("MCPURL_CONFIG", path)
}

func TestNewOptionOverridesProfile(t *testing.T) {
	writeConfig(t)
	t.Setenv("MCPURL_TEST_SUFFIX", "prod")

	a, err := New(Options{
		Target:   "@acme",
		ClientID: "override",
		Scopes:   []string{"a", "b"},
		Headers:  []string{"X-Extra: $MCPURL_TEST_SUFFIX"},
	}, io.Discard)
	require.NoError(t, err)
	assert.Equal(t, "override", a.prof.ClientID, "option client-id must win")
	assert.Equal(t, []string{"a", "b"}, a.prof.Scopes)
	assert.Equal(t, 18075, a.prof.CallbackPort, "profile callbackPort must survive")
	assert.Equal(t, "team-prod", a.headers.Get("X-Team"), "profile header env expansion")
	assert.Equal(t, "prod", a.headers.Get("X-Extra"), "option header env expansion")
	assert.Equal(t, "https://mcp.acme.example/mcp", a.prof.URL)
}

func TestNewErrors(t *testing.T) {
	writeConfig(t)
	_, err := New(Options{Target: "@nope"}, io.Discard)
	require.Error(t, err, "unknown profile must fail")

	_, err = New(Options{Target: "http://corp.internal/mcp"}, io.Discard)
	require.Error(t, err, "plain http for non-loopback must fail without AllowHTTP")

	_, err = New(Options{Target: "http://corp.internal/mcp", AllowHTTP: true}, io.Discard)
	require.NoError(t, err, "AllowHTTP must permit it")

	_, err = New(Options{Target: "@acme", Headers: []string{"no-colon"}}, io.Discard)
	require.Error(t, err, "malformed header must fail")

	_, err = New(Options{Target: "@acme", BearerEnv: "MCPURL_TEST_UNSET_VAR"}, io.Discard)
	require.Error(t, err, "unset bearer-env must fail at construction")
}

func TestNewWithoutTarget(t *testing.T) {
	writeConfig(t)
	a, err := New(Options{}, io.Discard)
	require.NoError(t, err)
	assert.NoError(t, a.Show(io.Discard, "acme"), "Show without target resolution") //nolint:testifylint // value check
	// claude-config must not enforce the scheme check — it only renders.
	assert.NoError(t, a.ClaudeConfig(io.Discard, "@acme", "")) //nolint:testifylint // value check
}

// A profile without a clientID uses dynamic registration: show names the
// registered client, and every command that drops the profile's token —
// logout (no clientID needed any more), logout --all, uninstall — drops the
// registration with it.
func TestDynamicClient(t *testing.T) {
	const endpoint = "https://mcp.dyn.example/mcp"
	clientKey := oauth.Key(endpoint, "http://127.0.0.1:18075/callback")
	tokenKey := oauth.Key(endpoint, "dyn-7")

	// setup gives each case its own config and stores: a registration and
	// the token issued to it.
	setup := func(t *testing.T) (clients *oauth.ClientStore, tokens *oauth.FileStore) {
		t.Helper()
		t.Setenv("HOME", t.TempDir())
		path := filepath.Join(t.TempDir(), "config.toml")
		require.NoError(t, os.WriteFile(path, []byte("[profiles.dyn]\nurl = \""+endpoint+"\"\n"), 0o600))
		t.Setenv("MCPURL_CONFIG", path)

		clients = &oauth.ClientStore{Dir: oauth.ClientsDir()}
		require.NoError(t, clients.Save(clientKey, &oauth.Registration{ClientID: "dyn-7", Issuer: "https://mcp.dyn.example",
			RegisteredAt: time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)}))
		tokens = &oauth.FileStore{Dir: oauth.TokensDir()}
		require.NoError(t, tokens.Save(tokenKey, &oauth.Token{AccessToken: "dyn-access"}))
		return clients, tokens
	}

	t.Run("show names the registered client", func(t *testing.T) {
		setup(t)
		a, err := New(Options{}, io.Discard)
		require.NoError(t, err)
		var shown bytes.Buffer
		require.NoError(t, a.Show(&shown, "dyn"))
		assert.Contains(t, shown.String(), "clientID:     dyn-7 (registered dynamically 2026-10-05)")
	})

	tests := []struct {
		name   string
		target string
		run    func(a *App) error
	}{
		{"logout", "@dyn", func(a *App) error { return a.Logout() }},
		{"logout --all", "", func(a *App) error { return a.LogoutAll() }},
		{"uninstall", "", func(a *App) error { return a.Uninstall("claude-desktop", "dyn") }},
	}
	for _, tt := range tests {
		t.Run(tt.name+" drops the registration", func(t *testing.T) {
			clients, tokens := setup(t)
			var msg bytes.Buffer
			a, err := New(Options{Target: tt.target, NoKeychain: true}, &msg)
			require.NoError(t, err)

			require.NoError(t, tt.run(a))
			_, err = clients.Load(clientKey)
			require.ErrorIs(t, err, oauth.ErrNotFound)
			_, err = tokens.Load(tokenKey)
			require.ErrorIs(t, err, oauth.ErrNotFound)
			assert.Contains(t, msg.String(), "dropped tokens for "+endpoint)
			assert.Contains(t, msg.String(), "dropped client registration for "+endpoint)
		})
	}
}

// A server that refuses the credential ends the run on exit code 3, with its
// own explanation both in the error the CLI prints and in the JSON-RPC error
// the MCP client shows (docs/tasks/02-401-body-discarded.md).
func TestBridgeAuthFailure(t *testing.T) {
	writeConfig(t)
	t.Setenv("MCPURL_TEST_BEARER", "static-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		http.Error(w, `auth: invalid token: oidc: malformed jwt: unexpected signature algorithm "HS256"`,
			http.StatusUnauthorized)
	}))
	defer srv.Close()

	a, err := New(Options{Target: srv.URL, BearerEnv: "MCPURL_TEST_BEARER"}, io.Discard)
	require.NoError(t, err)

	const initReq = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`
	var out bytes.Buffer
	err = a.Bridge(context.Background(), strings.NewReader(initReq+"\n"), &out)
	require.Error(t, err)
	assert.True(t, IsAuthError(err), "must map to exit code 3")
	assert.Contains(t, err.Error(), "malformed jwt", "the server's diagnosis must reach stderr")
	assert.Contains(t, out.String(), `"code":-32603`)
	assert.Contains(t, out.String(), "malformed jwt", "…and the MCP client")
}

func TestCheckScheme(t *testing.T) {
	tests := []struct {
		url       string
		allowHTTP bool
		wantErr   bool
	}{
		{"https://x.io/mcp", false, false},
		{"http://127.0.0.1:8075/mcp", false, false},
		{"http://localhost:8075/mcp", false, false},
		{"http://corp.internal/mcp", false, true},
		{"http://corp.internal/mcp", true, false},
	}
	for _, tt := range tests {
		err := checkScheme(tt.url, tt.allowHTTP)
		if tt.wantErr {
			assert.Error(t, err, tt.url) //nolint:testifylint // table mixes ok/err rows
		} else {
			assert.NoError(t, err, tt.url) //nolint:testifylint // table mixes ok/err rows
		}
	}
}
