package app

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientConfigPath(t *testing.T) {
	for _, client := range []string{"claude-desktop", "cursor", "windsurf"} {
		p, err := clientConfigPath(client)
		require.NoError(t, err, client)
		assert.True(t, filepath.IsAbs(p), client)
	}
	_, err := clientConfigPath("vscode")
	require.Error(t, err, "unknown client must fail")
}

// The M6 acceptance case: a config already containing another server (pencil)
// keeps it intact; .bak is written; uninstall reverts the entry exactly.
func TestUpsertAndRemoveServerEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "claude_desktop_config.json")
	original := `{
  "globalShortcut": "Cmd+Space",
  "mcpServers": {
    "pencil": {"command": "/usr/local/bin/pencil-mcp", "args": ["--x"]}
  }
}
`
	require.NoError(t, os.WriteFile(path, []byte(original), 0o644))

	entry := map[string]any{"command": "/opt/homebrew/bin/mcpurl", "args": []any{"@acme"}}
	require.NoError(t, upsertServerEntry(path, "acme", entry, false, io.Discard))

	bak, err := os.ReadFile(path + ".bak")
	require.NoError(t, err, ".bak must exist")
	assert.Equal(t, original, string(bak), ".bak must be the pre-edit content")

	var root map[string]any
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &root), "result must be valid JSON")
	assert.Equal(t, "Cmd+Space", root["globalShortcut"], "unrelated keys intact")
	servers := root["mcpServers"].(map[string]any)
	assert.Contains(t, servers, "pencil", "existing server intact")
	assert.Equal(t, entry, servers["acme"])

	require.NoError(t, removeServerEntry(path, "acme"))
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &root))
	servers = root["mcpServers"].(map[string]any)
	assert.NotContains(t, servers, "acme")
	assert.Contains(t, servers, "pencil")

	require.Error(t, removeServerEntry(path, "acme"), "double uninstall must fail")
}

func TestUpsertCreatesMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "mcp.json")
	entry := map[string]any{"command": "/bin/mcpurl", "args": []any{"@x"}}
	require.NoError(t, upsertServerEntry(path, "x", entry, false, io.Discard))

	var root map[string]any
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &root))
	assert.Contains(t, root["mcpServers"].(map[string]any), "x")
	_, err = os.Stat(path + ".bak")
	assert.True(t, os.IsNotExist(err), "no .bak when there was no original")
}

func TestUpsertRefusesInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.json")
	require.NoError(t, os.WriteFile(path, []byte("{oops"), 0o644))
	err := upsertServerEntry(path, "x", map[string]any{}, false, io.Discard)
	require.Error(t, err, "must refuse to clobber a broken config")
	data, _ := os.ReadFile(path)
	assert.Equal(t, "{oops", string(data), "broken file left untouched")
}

func TestEnsureProfileAppendPreservesFile(t *testing.T) {
	writeConfig(t) // sets MCPURL_CONFIG with profile "acme" and a comment-free body
	a, err := New(Options{
		Target:   "https://mcp.newsrv.example/mcp",
		ClientID: "newsrv-cli",
		Scopes:   []string{"openid", "roles"},
	}, io.Discard)
	require.NoError(t, err)

	require.NoError(t, a.ensureProfile(io.Discard, "newsrv", false))

	raw, err := os.ReadFile(a.cfg.Path)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "[profiles.acme]", "existing content preserved verbatim")
	assert.Contains(t, string(raw), "[profiles.newsrv]")

	cfg, err := Load("")
	require.NoError(t, err)
	p, err := cfg.Resolve("@newsrv")
	require.NoError(t, err)
	assert.Equal(t, "https://mcp.newsrv.example/mcp", p.URL)
	assert.Equal(t, "newsrv-cli", p.ClientID)
	assert.Equal(t, []string{"openid", "roles"}, p.Scopes)

	// Same name, different URL → refuse.
	a2, err := New(Options{Target: "https://other.example/mcp", ClientID: "x"}, io.Discard)
	require.NoError(t, err)
	require.ErrorContains(t, a2.ensureProfile(io.Discard, "newsrv", false), "different --name")

	// Same name, same URL → reuse silently.
	a3, err := New(Options{Target: "https://mcp.newsrv.example/mcp"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a3.ensureProfile(io.Discard, "newsrv", false))
}

func TestInstallDryRunWritesNothing(t *testing.T) {
	writeConfig(t)
	t.Setenv("HOME", t.TempDir()) // clientConfigPath must never see the real home
	a, err := New(Options{Target: "https://dry.example/mcp", ClientID: "c"}, io.Discard)
	require.NoError(t, err)

	var out strings.Builder
	require.NoError(t, a.Install(&out, "claude-desktop", "", true))
	assert.Contains(t, out.String(), "[profiles.dry]", "dry-run shows the profile block")
	assert.Contains(t, out.String(), `"@dry"`, "dry-run shows the client entry")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.NotContains(t, cfg.Profiles, "dry", "dry-run must not persist the profile")
}
