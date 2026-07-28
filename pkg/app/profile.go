// Profiles: ~/.config/mcpurl/config.toml loading and "<url | @profile>"
// target resolution. No secrets live here — tokens are in the keychain/token
// store (pkg/oauth).

package app

import (
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

// Get looks up a profile by name (with or without the "@" prefix).
func (c *Config) Get(name string) (Profile, error) {
	name = strings.TrimPrefix(name, "@")
	p, ok := c.Profiles[name]
	if !ok {
		return Profile{}, fmt.Errorf("profile %q not found in %s (known: %s)",
			name, c.Path, strings.Join(c.Names(), ", "))
	}
	return p, nil
}

// Resolve maps a CLI target ("@name" or a bare URL) to a Profile.
func (c *Config) Resolve(target string) (Profile, error) {
	if strings.HasPrefix(target, "@") {
		p, err := c.Get(target)
		if err != nil {
			return Profile{}, err
		}
		if p.URL == "" {
			return Profile{}, fmt.Errorf("profile %q has no url", p.Name)
		}
		return p, nil
	}
	u, err := url.Parse(target)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return Profile{}, fmt.Errorf("target %q is neither @profile nor an http(s) URL", target)
	}
	return Profile{Name: "", URL: target}, nil
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
