package app

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sample = `
[profiles.acme]
url          = "https://mcp.acme.example/mcp"
clientID     = "acme-cli"
callbackPort = 18075
scopes       = ["openid", "profile", "roles", "offline_access"]

  [profiles.acme.headers]
  "X-Team" = "team-$TEAM_SUFFIX"

[profiles.plain]
url = "https://mcp.example.com/mcp"
`

func writeSample(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	require.NoError(t, os.WriteFile(p, []byte(sample), 0o600))
	return p
}

func TestLoadAndResolve(t *testing.T) {
	cfg, err := Load(writeSample(t))
	require.NoError(t, err)

	p, err := cfg.Resolve("@acme")
	require.NoError(t, err)
	assert.Equal(t, "acme-cli", p.ClientID)
	assert.Equal(t, 18075, p.CallbackPort)
	assert.Len(t, p.Scopes, 4)

	_, err = cfg.Resolve("@nope")
	require.Error(t, err, "unknown profile")

	u, err := cfg.Resolve("https://raw.example.com/mcp")
	require.NoError(t, err)
	assert.Equal(t, "https://raw.example.com/mcp", u.URL)

	_, err = cfg.Resolve("not-a-url")
	require.Error(t, err, "garbage target")
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	require.NoError(t, err)
	assert.Empty(t, cfg.Profiles)
}

func TestExpandHeaders(t *testing.T) {
	t.Setenv("TEAM_SUFFIX", "prod")
	got := ExpandHeaders(map[string]string{"X-Team": "team-$TEAM_SUFFIX", "X-Plain": "v"})
	assert.Equal(t, map[string]string{"X-Team": "team-prod", "X-Plain": "v"}, got)
}

func TestBearerFromEnv(t *testing.T) {
	t.Setenv("TOKEN", "plain")
	t.Setenv("MY_TOKEN", "prefixed")
	assert.Equal(t, "prefixed", BearerFromEnv("TOKEN"), "MY_ prefix must win")
	t.Setenv("MY_TOKEN", "")
	assert.Equal(t, "plain", BearerFromEnv("TOKEN"), "fallback to plain name")
}
