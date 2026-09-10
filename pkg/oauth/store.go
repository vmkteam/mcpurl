// Token storage: OS keychain by default, plain files as fallback, plus the
// cross-process file lock that serializes token refresh (04-oauth.md).

package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vmkteam/mcpurl/pkg/atomicfile"
)

// Token is the stored value. Expiry is absolute (never a relative
// expires_in) — that was one of mcp-remote's historical failure modes.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	Expiry       time.Time `json:"expiry,omitzero"`
	Issuer       string    `json:"issuer,omitempty"`
	ClientID     string    `json:"client_id,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
}

// Fresh reports whether the access token is usable: non-empty and not within
// skew of expiry. A zero Expiry means the AS sent no expires_in — treat as
// fresh and rely on reactive 401 handling.
func (t *Token) Fresh(skew time.Duration) bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	return t.Expiry.IsZero() || time.Until(t.Expiry) > skew
}

// ErrNotFound is returned by Load when no token is stored under the key.
var ErrNotFound = errors.New("no stored token")

// Store persists tokens under an opaque key.
type Store interface {
	Load(key string) (*Token, error)
	Save(key string, t *Token) error
	Delete(key string) error
}

// Key derives the storage key: sha256(canonicalURL + \x00 + clientID),
// hex-truncated to 16 chars.
func Key(canonicalURL, clientID string) string {
	sum := sha256.Sum256([]byte(canonicalURL + "\x00" + clientID))
	return hex.EncodeToString(sum[:])[:16]
}

// FileStore keeps tokens as 0600 JSON files with atomic writes.
type FileStore struct {
	Dir string // e.g. ~/.config/mcpurl/tokens
}

func (s *FileStore) path(key string) string { return filepath.Join(s.Dir, key+".json") }

func (s *FileStore) Load(key string) (*Token, error) {
	data, err := os.ReadFile(s.path(key))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("corrupt token file %s: %w", s.path(key), err)
	}
	return &t, nil
}

func (s *FileStore) Save(key string, t *Token) error {
	data, err := json.Marshal(t) // #nosec G117 -- this IS the token store; 0600 file, explicit fallback backend
	if err != nil {
		return err
	}
	return writeFileAtomic(s.Dir, key+".json", data)
}

// writeFileAtomic writes data as dir/name with 0600 via tmp + rename. Token
// files are ours alone, so the mode is fixed rather than preserved.
func writeFileAtomic(dir, name string, data []byte) error {
	return atomicfile.Write(filepath.Join(dir, name), data, 0o600)
}

func (s *FileStore) Delete(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// BaseDir is ~/.config/mcpurl (shared with pkg/profile's default).
func BaseDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".mcpurl"
	}
	return filepath.Join(home, ".config", "mcpurl")
}

// TokensDir holds file-backend tokens; LockDir holds refresh flocks. The
// subdirectory names live here so callers never spell the layout themselves.
func TokensDir() string { return filepath.Join(BaseDir(), "tokens") }
func LockDir() string   { return filepath.Join(BaseDir(), "locks") }

// WipeFiles removes every file-backend token (`mcpurl logout --all`
// leftovers from bare-URL runs; keychain entries are deleted per key).
func WipeFiles() error { return os.RemoveAll(TokensDir()) }
