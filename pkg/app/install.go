// install/uninstall: write the mcpServers entry into an MCP client's config
// (02-cli.md). The JSON merge is surgical — only mcpServers.<name> changes —
// and a .bak copy is written first. The config.toml side is edited as text
// (one [profiles.<name>] block), so comments and other profiles survive.

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/vmkteam/mcpurl/pkg/atomicfile"
)

// knownClients is the single list of MCP clients install/uninstall know how
// to configure: the --client flag help, the "unknown client" error and the
// uninstall cross-check (a profile may back entries in several clients) all
// read it, so adding a client is one edit here plus one case below.
var knownClients = []string{"claude-desktop", "cursor", "windsurf"}

// Clients lists the supported MCP clients, for the CLI's flag help.
func Clients() []string { return slices.Clone(knownClients) }

// clientConfigPath locates the MCP client's config file for this OS.
func clientConfigPath(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch client {
	case "claude-desktop":
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "windows":
			return filepath.Join(os.Getenv("APPDATA"), "Claude", "claude_desktop_config.json"), nil
		default:
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil
	default:
		return "", fmt.Errorf("unknown client %q (want %s)", client, strings.Join(knownClients, ", "))
	}
}

// Install ensures a profile exists for the target (persisting one when given
// a bare URL) and upserts the client config entry referencing it. With
// dryRun, nothing is written — the would-be results go to w.
func (a *App) Install(w io.Writer, client, name string, dryRun bool) error {
	path, err := clientConfigPath(client)
	if err != nil {
		return err
	}

	// Name is set only when the target resolved to a stored profile; a URL
	// target has to persist one first.
	profName := a.prof.Name
	if profName == "" {
		if profName = name; profName == "" {
			profName = hostLabel(a.prof.URL)
		}
		if perr := a.ensureProfile(w, profName, dryRun); perr != nil {
			return perr
		}
	}
	entryName := name
	if entryName == "" {
		entryName = profName
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating own binary: %w", err)
	}
	// Absolute path on purpose: MCP clients don't inherit the shell PATH.
	entry := serverEntry{Command: exe, Args: []string{"@" + profName}}
	if err := upsertServerEntry(path, entryName, entry, dryRun, w); err != nil {
		return err
	}
	if !dryRun {
		fmt.Fprintf(a.msg, "installed %q into %s (backup: .bak)\n", entryName, path)
		fmt.Fprintf(a.msg, "restart %s to pick it up\n", client)
	}
	return nil
}

// Uninstall is the full undo of install: the client entry, the profile it
// references and the tokens stored for it. Each part is best-effort — a
// half-installed setup (entry already gone, profile still in config.toml) is
// exactly what needs cleaning up — and only an empty result is an error.
// The name may be written with or without the "@" prefix.
func (a *App) Uninstall(client, name string) error {
	name = strings.TrimPrefix(name, "@")
	path, err := clientConfigPath(client)
	if err != nil {
		return err
	}

	// The entry name and the profile name can differ (install --name), so the
	// profile to drop is the one the entry actually points at.
	profName := name
	entry, entryGone, err := removeServerEntry(path, name)
	if err != nil {
		return err
	}
	if entryGone {
		fmt.Fprintf(a.msg, "removed %q from %s (backup: .bak)\n", name, path)
		if cmd := entryCommand(entry); cmd != "" && !ownBinary(cmd) {
			// Not ours: uninstall is destructive and the name was a guess.
			a.warnf("%q was not an mcpurl entry (command: %s) — restore it from %s.bak if that was a typo",
				name, cmd, path)
		}
		if ref := entryProfile(entry); ref != "" {
			profName = ref
		}
	} else {
		fmt.Fprintf(a.msg, "no entry %q in %s\n", name, path)
	}

	prof, hadProfile := a.cfg.Profiles[profName]
	if hadProfile {
		if err := a.editProfileBlock(profName, ""); err != nil {
			return err
		}
		delete(a.cfg.Profiles, profName)
		fmt.Fprintf(a.msg, "removed profile @%s from %s (backup: .bak)\n", profName, a.cfg.Path)
		// Tokens are keyed by url+clientID: once the profile is gone there is
		// no target left to `logout` with, so drop them here.
		a.dropTokens(a.store(), prof)
		a.warnOtherClients(client, profName)
	} else {
		fmt.Fprintf(a.msg, "no profile @%s in %s\n", profName, a.cfg.Path)
	}
	if !entryGone && !hadProfile {
		return fmt.Errorf("nothing to remove: no entry %q in %s and no profile @%s in %s",
			name, path, profName, a.cfg.Path)
	}
	return nil
}

// warnOtherClients reports entries in the other clients' configs that still
// reference the profile just removed — they would break silently otherwise.
func (a *App) warnOtherClients(skip, profName string) {
	for _, client := range knownClients {
		if client == skip {
			continue
		}
		path, err := clientConfigPath(client)
		if err != nil {
			continue
		}
		root, original, err := loadClientConfig(path)
		if err != nil || original == nil {
			continue
		}
		servers, _ := root["mcpServers"].(map[string]any)
		for _, entryName := range slices.Sorted(maps.Keys(servers)) {
			if entryProfile(servers[entryName]) == profName {
				a.warnf("%s still has entry %q pointing at @%s (%s)", client, entryName, profName, path)
			}
		}
	}
}

// entryProfile extracts the "@profile" argument from a client config entry as
// loaded from JSON (map form — the typed serverEntry only goes the other way).
func entryProfile(entry any) string {
	e, _ := entry.(map[string]any)
	args, _ := e["args"].([]any)
	for _, arg := range args {
		if s, ok := arg.(string); ok && strings.HasPrefix(s, "@") {
			return strings.TrimPrefix(s, "@")
		}
	}
	return ""
}

// entryCommand reports the binary a client config entry launches.
func entryCommand(entry any) string {
	e, _ := entry.(map[string]any)
	cmd, _ := e["command"].(string)
	return cmd
}

// ownBinary reports whether a command path launches mcpurl itself (install
// writes an absolute path; Windows adds the .exe suffix).
func ownBinary(cmd string) bool {
	return strings.TrimSuffix(filepath.Base(cmd), ".exe") == "mcpurl"
}

// ensureProfile persists the profile for a bare-URL install. A new profile is
// APPENDED, so the existing file (comments included) is untouched; an existing
// one is updated in place — re-running install with a new URL or new flags is
// how you change a profile, not an error.
func (a *App) ensureProfile(w io.Writer, name string, dryRun bool) error {
	desired := a.prof
	existing, exists := a.cfg.Profiles[name]
	if exists {
		if desired = mergeProfile(existing, a.prof); sameProfile(existing, desired) {
			fmt.Fprintf(a.msg, "profile @%s already exists, reusing\n", name)
			return nil
		}
	}
	desired.Name = name

	block := profileTOML(name, desired)
	if dryRun {
		verb := "append to"
		if exists {
			verb = "update in"
		}
		fmt.Fprintf(w, "# would %s %s:\n%s", verb, a.cfg.Path, block)
		return nil
	}
	if exists {
		if err := a.editProfileBlock(name, block); err != nil {
			return err
		}
		fmt.Fprintf(a.msg, "profile @%s updated in %s (backup: .bak)\n", name, a.cfg.Path)
	} else {
		if err := appendProfile(a.cfg.Path, block); err != nil {
			return err
		}
		fmt.Fprintf(a.msg, "profile @%s saved to %s\n", name, a.cfg.Path)
	}
	a.cfg.Profiles[name] = desired
	return nil
}

// mergeProfile overlays a fresh install onto the stored profile: the URL is
// whatever install was pointed at, the rest only when the flag was given —
// unmentioned settings (headers above all) must survive the rewrite.
func mergeProfile(old, fresh Profile) Profile {
	out := old
	out.URL = fresh.URL
	if fresh.ClientID != "" {
		out.ClientID = fresh.ClientID
	}
	if len(fresh.Scopes) > 0 {
		out.Scopes = fresh.Scopes
	}
	if fresh.CallbackPort != 0 {
		out.CallbackPort = fresh.CallbackPort
	}
	if fresh.Issuer != "" {
		out.Issuer = fresh.Issuer
	}
	if fresh.BearerEnv != "" {
		out.BearerEnv = fresh.BearerEnv
	}
	return out
}

// sameProfile compares the fields profileTOML writes (headers are carried over
// verbatim by mergeProfile, so they can never differ here).
func sameProfile(a, b Profile) bool {
	return a.URL == b.URL && a.ClientID == b.ClientID && a.CallbackPort == b.CallbackPort &&
		a.Issuer == b.Issuer && a.BearerEnv == b.BearerEnv && slices.Equal(a.Scopes, b.Scopes)
}

func appendProfile(path, block string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(block)
	return err
}

// editProfileBlock rewrites config.toml with the profile's block replaced by
// block ("" deletes it), keeping a .bak of the previous content.
func (a *App) editProfileBlock(name, block string) error {
	original, err := os.ReadFile(a.cfg.Path)
	if err != nil {
		return err
	}
	out, ok := spliceProfileBlock(string(original), name, block)
	if !ok {
		return fmt.Errorf("profile @%s is not a [profiles.%s] section in %s — edit the file by hand",
			name, name, a.cfg.Path)
	}
	return replaceConfig(a.cfg.Path, original, []byte(out))
}

// replaceConfig is how mcpurl rewrites a user's config file: keep a .bak of
// what was there, then swap in the new content atomically. Both config files
// (config.toml, the client JSON) go through here, so the backup convention
// lives in one place.
func replaceConfig(path string, original, data []byte) error {
	if original != nil {
		if err := os.WriteFile(path+".bak", original, 0o600); err != nil {
			return fmt.Errorf("writing backup: %w", err)
		}
	}
	return atomicfile.Write(path, data, 0o600)
}

// profileTOML renders the block: only what discovery can't provide, plus any
// headers already stored (a rewrite must not lose them).
func profileTOML(name string, p Profile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n[profiles.%s]\nurl = %q\n", name, p.URL)
	if p.ClientID != "" {
		fmt.Fprintf(&b, "clientID = %q\n", p.ClientID)
	}
	if p.CallbackPort != 0 {
		fmt.Fprintf(&b, "callbackPort = %d\n", p.CallbackPort)
	}
	if len(p.Scopes) > 0 {
		quoted := make([]string, len(p.Scopes))
		for i, s := range p.Scopes {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		fmt.Fprintf(&b, "scopes = [%s]\n", strings.Join(quoted, ", "))
	}
	if p.Issuer != "" {
		fmt.Fprintf(&b, "issuer = %q\n", p.Issuer)
	}
	if p.BearerEnv != "" {
		fmt.Fprintf(&b, "bearerEnv = %q\n", p.BearerEnv)
	}
	if len(p.Headers) > 0 {
		fmt.Fprintf(&b, "\n  [profiles.%s.headers]\n", name)
		for _, k := range slices.Sorted(maps.Keys(p.Headers)) {
			fmt.Fprintf(&b, "  %q = %q\n", k, p.Headers[k])
		}
	}
	return b.String()
}

func hostLabel(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		return strings.Split(u.Hostname(), ".")[0]
	}
	return "mcp"
}

// loadClientConfig reads and parses the client config; a missing file yields
// an empty document, invalid JSON is refused (never clobber a broken file).
func loadClientConfig(path string) (root map[string]any, original []byte, err error) {
	original, err = os.ReadFile(path)
	if os.IsNotExist(err) {
		return map[string]any{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	root = map[string]any{}
	if len(bytes.TrimSpace(original)) > 0 {
		if err := json.Unmarshal(original, &root); err != nil {
			return nil, nil, fmt.Errorf("%s is not valid JSON (fix it first): %w", path, err)
		}
	}
	return root, original, nil
}

func writeClientConfig(path string, root map[string]any, original []byte) error {
	out, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return replaceConfig(path, original, out)
}

// serverEntry is the client-config record: absolute binary path + profile ref.
type serverEntry struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

// upsertServerEntry sets mcpServers.<name>, leaving everything else as the
// JSON round-trip preserves it (content-identical; formatting normalized).
func upsertServerEntry(path, name string, entry any, dryRun bool, w io.Writer) error {
	root, original, err := loadClientConfig(path)
	if err != nil {
		return err
	}
	servers, _ := root["mcpServers"].(map[string]any)
	if servers == nil {
		servers = map[string]any{}
	}
	servers[name] = entry
	root["mcpServers"] = servers

	if dryRun {
		out, err := json.MarshalIndent(root, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "# would write to %s:\n%s\n", path, out)
		return nil
	}
	return writeClientConfig(path, root, original)
}

// removeServerEntry deletes mcpServers.<name> and returns what it deleted (so
// the caller can see which profile the entry referenced). A missing file or a
// missing entry is reported as ok == false, not as an error: uninstall keeps
// going and cleans up the profile side.
func removeServerEntry(path, name string) (entry any, ok bool, err error) {
	root, original, err := loadClientConfig(path)
	if err != nil {
		return nil, false, err
	}
	if original == nil {
		return nil, false, nil
	}
	servers, _ := root["mcpServers"].(map[string]any)
	entry, ok = servers[name]
	if !ok {
		return nil, false, nil
	}
	delete(servers, name)
	return entry, true, writeClientConfig(path, root, original)
}
