package atomicfile

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteCreatesAndReplaces(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "config.toml")
	require.NoError(t, Write(path, []byte("one\n"), 0o600))

	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), fi.Mode().Perm())

	require.NoError(t, Write(path, []byte("two\n"), Mode(path, 0o600)))
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, "two\n", string(data))

	// The temp file must not survive a successful write.
	entries, err := os.ReadDir(filepath.Dir(path))
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no .tmp-* leftovers")
}

// Config files symlinked out of a dotfiles repository are the common case
// this must not break: rename over the link would detach it, leaving the user
// editing a file mcpurl no longer reads.
func TestWriteFollowsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles", "mcpurl.toml")
	link := filepath.Join(dir, "config", "config.toml")
	require.NoError(t, os.MkdirAll(filepath.Dir(target), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Dir(link), 0o700))
	require.NoError(t, os.WriteFile(target, []byte("old\n"), 0o600))
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, Write(link, []byte("new\n"), Mode(link, 0o600)))

	fi, err := os.Lstat(link)
	require.NoError(t, err)
	assert.NotZero(t, fi.Mode()&os.ModeSymlink, "the symlink must survive the write")

	data, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Equal(t, "new\n", string(data), "the write must land in the link target")
}

// A user's config keeps the mode they gave it; only a new file gets 0600.
func TestModePreservesExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mcp.json")
	require.NoError(t, os.WriteFile(path, []byte("{}"), 0o644))
	assert.Equal(t, os.FileMode(0o644), Mode(path, 0o600))

	require.NoError(t, Write(path, []byte("{}\n"), Mode(path, 0o600)))
	fi, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), fi.Mode().Perm(), "replacing must not tighten the mode")

	assert.Equal(t, os.FileMode(0o600), Mode(filepath.Join(t.TempDir(), "absent"), 0o600))
}
