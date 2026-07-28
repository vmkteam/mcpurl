// install/uninstall: write the mcpServers entry into an MCP client's config
// (02-cli.md). The JSON merge is surgical — only mcpServers.<name> changes —
// and a .bak copy is written first.

package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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
		return "", fmt.Errorf("unknown client %q (want claude-desktop, cursor or windsurf)", client)
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

	profName := strings.TrimPrefix(a.opts.Target, "@")
	if !strings.HasPrefix(a.opts.Target, "@") {
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

// Uninstall removes the entry (and nothing else); profile and tokens stay.
func (a *App) Uninstall(client, name string) error {
	path, err := clientConfigPath(client)
	if err != nil {
		return err
	}
	if err := removeServerEntry(path, name); err != nil {
		return err
	}
	fmt.Fprintf(a.msg, "removed %q from %s (backup: .bak)\n", name, path)
	return nil
}

// ensureProfile persists a profile for a bare-URL install by APPENDING a TOML
// block — the existing file (comments included) is never rewritten. A name
// clash with a different URL is an error, not an overwrite.
func (a *App) ensureProfile(w io.Writer, name string, dryRun bool) error {
	if p, ok := a.cfg.Profiles[name]; ok {
		if p.URL == a.prof.URL {
			fmt.Fprintf(a.msg, "profile @%s already exists, reusing\n", name)
			return nil
		}
		return fmt.Errorf("profile @%s already points at %s — pass a different --name", name, p.URL)
	}

	block := profileTOML(name, a.prof)
	if dryRun {
		fmt.Fprintf(w, "# would append to %s:\n%s", a.cfg.Path, block)
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.cfg.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(a.cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(block); err != nil {
		return err
	}
	fmt.Fprintf(a.msg, "profile @%s saved to %s\n", name, a.cfg.Path)
	return nil
}

// profileTOML renders the appended block: only what discovery can't provide.
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
	if original != nil {
		if err := os.WriteFile(path+".bak", original, 0o600); err != nil {
			return fmt.Errorf("writing backup: %w", err)
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, out, 0o600)
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

func removeServerEntry(path, name string) error {
	root, original, err := loadClientConfig(path)
	if err != nil {
		return err
	}
	if original == nil {
		return fmt.Errorf("%s does not exist", path)
	}
	servers, _ := root["mcpServers"].(map[string]any)
	if _, ok := servers[name]; !ok {
		return fmt.Errorf("no entry %q in %s", name, path)
	}
	delete(servers, name)
	return writeClientConfig(path, root, original)
}
