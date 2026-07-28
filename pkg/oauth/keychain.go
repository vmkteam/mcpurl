package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/zalando/go-keyring"
)

const (
	keychainService = "mcpurl"
	keychainAccount = "encryption-key" // one random key for all token files
)

// KeychainStore keeps tokens as AES-256-GCM encrypted files under the token
// dir, with the random key in the OS keychain. The secret material itself
// cannot live in the keychain: real-world tokens are two JWTs and routinely
// exceed the item size limits (~3 KB on macOS via go-keyring — "data passed
// to Set was too big").
type KeychainStore struct{ files FileStore }

func (s KeychainStore) path(key string) string { return filepath.Join(s.files.Dir, key+".enc") }

func (s KeychainStore) Load(key string) (*Token, error) {
	data, err := os.ReadFile(s.path(key))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	mk, err := masterKey(false)
	if errors.Is(err, ErrNotFound) {
		// Key vanished from the keychain: the file is unreadable garbage —
		// treat as logged out, the next 401 triggers a fresh login.
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	plain, err := decrypt(mk, data)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s (keychain key changed?): %w", s.path(key), err)
	}
	var t Token
	if err := json.Unmarshal(plain, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func (s KeychainStore) Save(key string, t *Token) error {
	mk, err := masterKey(true)
	if err != nil {
		return fmt.Errorf("keychain: %w", err)
	}
	plain, err := json.Marshal(t)
	if err != nil {
		return err
	}
	sealed, err := encrypt(mk, plain)
	if err != nil {
		return err
	}
	return writeFileAtomic(s.files.Dir, key+".enc", sealed)
}

func (s KeychainStore) Delete(key string) error {
	if err := os.Remove(s.path(key)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// masterKey loads (or, with create, generates and stores) the 32-byte
// encryption key. Generation happens under the refresh/login flock, so two
// racing processes cannot mint different keys.
func masterKey(create bool) ([]byte, error) {
	v, err := keyring.Get(keychainService, keychainAccount)
	switch {
	case err == nil:
		return base64.StdEncoding.DecodeString(v)
	case errors.Is(err, keyring.ErrNotFound) && create:
		k := make([]byte, 32)
		if _, rerr := rand.Read(k); rerr != nil {
			return nil, rerr
		}
		if serr := keyring.Set(keychainService, keychainAccount, base64.StdEncoding.EncodeToString(k)); serr != nil {
			return nil, serr
		}
		return k, nil
	case errors.Is(err, keyring.ErrNotFound):
		return nil, ErrNotFound
	default:
		return nil, err
	}
}

func encrypt(key, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

func decrypt(key, sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
}

// NewStore selects the backend: keychain-encrypted files on darwin /
// linux-with-secret-service, plain files otherwise or when forced
// (--no-keychain; windows v1 uses plain files).
func NewStore(noKeychain bool) Store {
	fileStore := FileStore{Dir: TokensDir()}
	if noKeychain || runtime.GOOS == "windows" {
		return &fileStore
	}
	// Probe: a Get for an unused key must yield ErrNotFound if the keychain
	// works; any other error (no dbus secret service etc.) → file fallback.
	if _, err := keyring.Get(keychainService, "availability-probe"); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return &fileStore
	}
	return KeychainStore{files: fileStore}
}
