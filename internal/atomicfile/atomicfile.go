// Package atomicfile writes a file so that readers see either the previous
// content or the new one, never a half-written mix.
//
// mcpurl replaces three kinds of file this way — the token store, the profile
// config and an MCP client's JSON — and all three are read by other processes
// (a second bridge instance, Claude Desktop) while mcpurl runs. A plain
// os.WriteFile truncates first, so an interrupted write leaves a config the
// client refuses to parse. One implementation, one place to audit the
// tmp-cleanup and permission handling.
package atomicfile

import (
	"os"
	"path/filepath"
)

// Write replaces path with data via a temp file in the same directory plus a
// rename. Missing parent directories are created 0700; the temp file gets
// mode before it is renamed, so the file is never briefly world-readable.
//
// A symlink is followed, not replaced: config files under a dotfiles
// repository are routinely symlinked into ~/.config, and renaming over the
// link would detach it — mcpurl would keep writing a file the user no longer
// edits, in silence.
func Write(path string, data []byte, mode os.FileMode) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
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

// Mode reports the mode Write should use to replace path: the existing file's,
// or fallback for a new one. Configs belong to the user — replacing one must
// not quietly tighten or loosen it.
func Mode(path string, fallback os.FileMode) os.FileMode {
	if fi, err := os.Stat(path); err == nil {
		return fi.Mode().Perm()
	}
	return fallback
}
