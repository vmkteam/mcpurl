// Profiles: ~/.config/mcpurl/config.toml loading and "<url | @profile>"
// target resolution. No secrets live here — tokens are in the keychain/token
// store (pkg/oauth).

package app

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// Profile is one [profiles.<name>] TOML section.
type Profile struct {
	Name         string            `toml:"-"`
	URL          string            `toml:"url"`
	ClientID     string            `toml:"clientID"`
	CallbackPort int               `toml:"callbackPort"`
	Scopes       []string          `toml:"scopes"`
	Issuer       string            `toml:"issuer"`
	BearerEnv    string            `toml:"bearerEnv"`
	Headers      map[string]string `toml:"headers"`
}

// Config is the whole config.toml.
type Config struct {
	Profiles map[string]Profile `toml:"profiles"`
	Path     string             `toml:"-"`
}

// DefaultPath honors MCPURL_CONFIG, else ~/.config/mcpurl/config.toml
// (pcurl-style, deliberately not ~/Library on macOS).
func DefaultPath() string {
	if p := os.Getenv("MCPURL_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.toml"
	}
	return filepath.Join(home, ".config", "mcpurl", "config.toml")
}

// Load reads the config; a missing file yields an empty config, not an error.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultPath()
	}
	cfg := &Config{Profiles: map[string]Profile{}, Path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	if err := toml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for name, p := range cfg.Profiles {
		p.Name = name
		cfg.Profiles[name] = p
	}
	return cfg, nil
}

// Get looks up a stored profile by name (with or without the "@" prefix).
// Unlike Resolve it never accepts a URL — the caller means a profile.
func (c *Config) Get(name string) (Profile, error) {
	name = strings.TrimPrefix(name, "@")
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("%q is not a profile in %s (known: %s)",
			name, c.Path, strings.Join(c.Names(), ", "))
	}
	return p, nil
}

// Resolve maps a CLI target to a Profile. The target is an http(s) URL, or a
// profile name written either way: the "@" is a readability marker, never a
// requirement — every command accepts both spellings.
func (c *Config) Resolve(target string) (Profile, error) {
	if isHTTPURL(target) {
		return Profile{Name: "", URL: target}, nil
	}
	if strings.TrimPrefix(target, "@") == "" {
		return Profile{}, errors.New("empty target: want a profile name or an http(s) URL")
	}
	p, err := c.Get(target)
	if err != nil {
		// Name both readings: a mistyped URL lands here too, and the profile
		// lookup alone would send the user looking in the wrong file.
		return Profile{}, fmt.Errorf("%w and not an http(s) URL", err)
	}
	if p.URL == "" {
		return Profile{}, fmt.Errorf("profile %q has no url", p.Name)
	}
	return p, nil
}

// isHTTPURL reports whether target is a usable http(s) endpoint rather than a
// profile name. A scheme is required: "example.com/mcp" is ambiguous, and
// treating it as a profile name yields the message that lists both readings.
func isHTTPURL(target string) bool {
	u, err := url.Parse(target)
	return err == nil && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}

// Names returns profile names, sorted.
func (c *Config) Names() []string {
	return slices.Sorted(maps.Keys(c.Profiles))
}

// ExpandHeaders resolves $VAR / ${VAR} in header values from the
// environment. Unset variables expand to "".
func ExpandHeaders(h map[string]string) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := make(map[string]string, len(h))
	for k, v := range h {
		out[k] = os.ExpandEnv(v)
	}
	return out
}

// BearerFromEnv implements the vmkteam convention: MY_<NAME> wins over
// <NAME>. Returns "" when neither is set.
func BearerFromEnv(name string) string {
	if v := os.Getenv("MY_" + name); v != "" {
		return v
	}
	return os.Getenv(name)
}
