package app

import (
	"io"
	"os"
	"path/filepath"
	"testing"

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
