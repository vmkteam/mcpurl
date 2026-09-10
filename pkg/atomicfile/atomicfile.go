// Package atomicfile replaces a file so readers see either the old content or
// the new one, never a half-written mix. mcpurl rewrites the token store, the
// profile config and an MCP client's JSON while other processes (a second
// bridge, Claude Desktop) read them; os.WriteFile truncates first, so an
// interrupted write leaves a config the client refuses to parse.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data via a temp file in the same directory plus a
// rename, creating missing parents 0700.
//
// mode applies to a new file only — an existing one keeps its own, the way
// os.WriteFile behaves; these are the user's configs, not ours to tighten. The
// temp file is chmod'ed before the rename, so the result is never briefly
// world-readable. A symlink is followed rather than replaced: a config
// symlinked out of a dotfiles repository must stay linked, or mcpurl would go
// on writing a file the user no longer edits, in silence.
func Write(path string, data []byte, mode os.FileMode) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // no-op after a successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close() //nolint:errcheck // the write already failed
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close() //nolint:errcheck // the write already failed
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
