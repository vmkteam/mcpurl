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
	for _, client := range knownClients {
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

	removed, ok, err := removeServerEntry(path, "acme")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "acme", entryProfile(removed), "removed entry reveals its profile")
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &root))
	servers = root["mcpServers"].(map[string]any)
	assert.NotContains(t, servers, "acme")
	assert.Contains(t, servers, "pencil")

	_, ok, err = removeServerEntry(path, "acme")
	require.NoError(t, err, "a second uninstall is not an error, just a no-op")
	assert.False(t, ok)
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

	// Same name, different URL → update in place, keeping flags not repeated.
	a2, err := New(Options{Target: "https://other.example/mcp"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a2.ensureProfile(io.Discard, "newsrv", false))

	cfg, err = Load("")
	require.NoError(t, err)
	p = cfg.Profiles["newsrv"]
	assert.Equal(t, "https://other.example/mcp", p.URL, "install must replace the URL")
	assert.Equal(t, "newsrv-cli", p.ClientID, "settings not passed again must survive")
	assert.Equal(t, []string{"openid", "roles"}, p.Scopes)
	assert.Len(t, cfg.Profiles, 2, "no duplicate [profiles.newsrv] block")
	raw, err = os.ReadFile(a.cfg.Path)
	require.NoError(t, err)
	assert.Contains(t, string(raw), "[profiles.acme]", "other profiles untouched")

	// Same name, same URL → reuse silently.
	a3, err := New(Options{Target: "https://other.example/mcp"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a3.ensureProfile(io.Discard, "newsrv", false))
}

// A rewrite must not drop a nested [profiles.<name>.headers] table: the user
// hand-wrote it, install never sees it as a flag.
func TestEnsureProfileUpdateKeepsHeaders(t *testing.T) {
	writeConfig(t) // profile "acme" with an X-Team header
	a, err := New(Options{Target: "https://acme.example/v2/mcp"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.ensureProfile(io.Discard, "acme", false))

	cfg, err := Load("")
	require.NoError(t, err)
	p := cfg.Profiles["acme"]
	assert.Equal(t, "https://acme.example/v2/mcp", p.URL)
	assert.Equal(t, "acme-cli", p.ClientID)
	assert.Equal(t, 18075, p.CallbackPort)
	assert.Equal(t, map[string]string{"X-Team": "team-$MCPURL_TEST_SUFFIX"}, p.Headers,
		"hand-written headers must survive the rewrite, unexpanded")

	bak, err := os.ReadFile(a.cfg.Path + ".bak")
	require.NoError(t, err)
	assert.Contains(t, string(bak), "https://mcp.acme.example/mcp", ".bak holds the pre-edit config")
}

// uninstall is destructive and takes a bare name: a typo that hits a foreign
// server entry must be called out, with the way back.
func TestUninstallWarnsOnForeignEntry(t *testing.T) {
	writeConfig(t)
	t.Setenv("HOME", t.TempDir())
	path, err := clientConfigPath("claude-desktop")
	require.NoError(t, err)
	require.NoError(t, upsertServerEntry(path, "pencil",
		map[string]any{"command": "/usr/local/bin/pencil-mcp", "args": []any{"--x"}}, false, io.Discard))

	var msg strings.Builder
	a, err := New(Options{}, &msg)
	require.NoError(t, err)
	require.NoError(t, a.Uninstall("claude-desktop", "pencil"))
	assert.Contains(t, msg.String(), "was not an mcpurl entry")
	assert.Contains(t, msg.String(), ".bak")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Contains(t, cfg.Profiles, "acme", "an unrelated profile must not be touched")
}

// Uninstall is the full undo: entry + profile, with or without the "@".
func TestUninstallRemovesEntryAndProfile(t *testing.T) {
	writeConfig(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	a, err := New(Options{Target: "@acme"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.Install(io.Discard, "claude-desktop", "", false))

	// A fresh App: uninstall runs in its own process.
	a2, err := New(Options{}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a2.Uninstall("claude-desktop", "@acme"), "@ prefix must be accepted")

	clientPath, err := clientConfigPath("claude-desktop")
	require.NoError(t, err)
	data, err := os.ReadFile(clientPath)
	require.NoError(t, err)
	var root map[string]any
	require.NoError(t, json.Unmarshal(data, &root))
	assert.NotContains(t, root["mcpServers"].(map[string]any), "acme")

	cfg, err := Load("")
	require.NoError(t, err)
	assert.NotContains(t, cfg.Profiles, "acme", "the profile must be gone too")
}

// The reported case: the entry was already removed, the profile lingered.
func TestUninstallCleansLeftoverProfile(t *testing.T) {
	writeConfig(t)
	t.Setenv("HOME", t.TempDir()) // no client config at all
	a, err := New(Options{}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.Uninstall("claude-desktop", "acme"))

	cfg, err := Load("")
	require.NoError(t, err)
	assert.NotContains(t, cfg.Profiles, "acme")

	// Nothing left anywhere → error, so a typo is not reported as success.
	require.ErrorContains(t, a.Uninstall("claude-desktop", "acme"), "nothing to remove")
}

// A bare profile name is a profile, not a URL: install must reference the
// existing one instead of minting a duplicate from the host label.
func TestInstallBareNameReusesProfile(t *testing.T) {
	writeConfig(t)
	t.Setenv("HOME", t.TempDir())
	a, err := New(Options{Target: "acme"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.Install(io.Discard, "claude-desktop", "", false))

	cfg, err := Load("")
	require.NoError(t, err)
	assert.Len(t, cfg.Profiles, 1, "no second profile from hostLabel()")
	assert.Contains(t, cfg.Profiles, "acme")

	path, err := clientConfigPath("claude-desktop")
	require.NoError(t, err)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var root map[string]any
	require.NoError(t, json.Unmarshal(data, &root))
	entry := root["mcpServers"].(map[string]any)["acme"]
	assert.Equal(t, "acme", entryProfile(entry), "the entry must point at @acme")
}

// install --name X @profile: the entry name differs from the profile name, so
// uninstall must follow the entry's args to find the profile to drop.
func TestUninstallFollowsEntryToProfile(t *testing.T) {
	writeConfig(t)
	t.Setenv("HOME", t.TempDir())
	a, err := New(Options{Target: "@acme"}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a.Install(io.Discard, "cursor", "acme-prod", false))

	a2, err := New(Options{}, io.Discard)
	require.NoError(t, err)
	require.NoError(t, a2.Uninstall("cursor", "acme-prod"))

	cfg, err := Load("")
	require.NoError(t, err)
	assert.NotContains(t, cfg.Profiles, "acme", "profile referenced by the entry must go")
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
