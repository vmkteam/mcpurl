package oauth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zalando/go-keyring"
)

func newKeychainStore(t *testing.T) KeychainStore {
	t.Helper()
	keyring.MockInit() // in-memory keyring, no OS keychain involved
	return KeychainStore{files: FileStore{Dir: t.TempDir()}}
}

// The regression that the first live Keycloak login caught: two real JWTs
// blow past the OS keychain item size limit, so the secret material must
// live in an encrypted file with only the key in the keychain.
func TestKeychainStoreBigTokenRoundTrip(t *testing.T) {
	s := newKeychainStore(t)
	key := Key("https://mcp.acme.example/mcp", "acme-cli")

	tok := &Token{
		AccessToken:  strings.Repeat("a", 8<<10), // 8 KB JWT-sized blob
		RefreshToken: strings.Repeat("r", 8<<10),
		Expiry:       time.Now().Add(time.Hour).UTC(),
		ClientID:     "acme-cli",
	}
	require.NoError(t, s.Save(key, tok))

	got, err := s.Load(key)
	require.NoError(t, err)
	assert.Equal(t, tok.AccessToken, got.AccessToken)
	assert.Equal(t, tok.RefreshToken, got.RefreshToken)

	// The on-disk file must be ciphertext, not the raw token.
	raw, err := os.ReadFile(filepath.Join(s.files.Dir, key+".enc"))
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "aaaa", "token material must not be on disk in plaintext")

	require.NoError(t, s.Delete(key))
	_, err = s.Load(key)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, s.Delete(key), "double delete is a no-op")
}

func TestKeychainStoreMissingKeyBehavesAsLoggedOut(t *testing.T) {
	s := newKeychainStore(t)
	key := Key("https://x/mcp", "c")
	require.NoError(t, s.Save(key, &Token{AccessToken: "a"}))

	// Simulate the key vanishing from the keychain.
	require.NoError(t, keyring.Delete(keychainService, keychainAccount))
	_, err := s.Load(key)
	require.ErrorIs(t, err, ErrNotFound, "unreadable file must read as logged out")
}

func TestKeychainStoreCorruptFile(t *testing.T) {
	s := newKeychainStore(t)
	key := Key("https://x/mcp", "c")
	require.NoError(t, s.Save(key, &Token{AccessToken: "a"}))
	require.NoError(t, os.WriteFile(filepath.Join(s.files.Dir, key+".enc"), []byte("garbage"), 0o600))
	_, err := s.Load(key)
	require.ErrorContains(t, err, "cannot decrypt")
}

func TestMasterKeyStableAcrossStores(t *testing.T) {
	keyring.MockInit()
	dir := t.TempDir()
	s1 := KeychainStore{files: FileStore{Dir: dir}}
	s2 := KeychainStore{files: FileStore{Dir: dir}}
	key := Key("https://x/mcp", "c")

	require.NoError(t, s1.Save(key, &Token{AccessToken: "shared"}))
	got, err := s2.Load(key) // second "process" reuses the stored key
	require.NoError(t, err)
	assert.Equal(t, "shared", got.AccessToken)
}
