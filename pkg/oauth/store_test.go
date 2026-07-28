package oauth

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKeyDeterministic(t *testing.T) {
	k1 := Key("https://mcp.acme.example/mcp", "acme-cli")
	k2 := Key("https://mcp.acme.example/mcp", "acme-cli")
	k3 := Key("https://mcp.acme.example/mcp", "other")
	assert.Equal(t, k1, k2)
	assert.NotEqual(t, k1, k3)
	assert.Len(t, k1, 16)
}

func TestFileStoreRoundTrip(t *testing.T) {
	s := &FileStore{Dir: t.TempDir()}
	key := Key("https://x/mcp", "c")

	_, err := s.Load(key)
	require.ErrorIs(t, err, ErrNotFound)

	tok := &Token{AccessToken: "a", RefreshToken: "r", Expiry: time.Now().Add(time.Hour).UTC(), ClientID: "c"}
	require.NoError(t, s.Save(key, tok))

	info, err := os.Stat(filepath.Join(s.Dir, key+".json"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())

	got, err := s.Load(key)
	require.NoError(t, err)
	assert.Equal(t, "a", got.AccessToken)
	assert.Equal(t, "r", got.RefreshToken)

	require.NoError(t, s.Delete(key))
	_, err = s.Load(key)
	require.ErrorIs(t, err, ErrNotFound)
	require.NoError(t, s.Delete(key), "double delete must be a no-op")
}

func TestFresh(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		tok  *Token
		want bool
	}{
		{"nil", nil, false},
		{"empty access", &Token{}, false},
		{"no expiry", &Token{AccessToken: "a"}, true},
		{"fresh", &Token{AccessToken: "a", Expiry: now.Add(time.Hour)}, true},
		{"near expiry", &Token{AccessToken: "a", Expiry: now.Add(30 * time.Second)}, false},
		{"expired", &Token{AccessToken: "a", Expiry: now.Add(-time.Hour)}, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, tt.tok.Fresh(60*time.Second), tt.name)
	}
}

func TestWithLockMutualExclusion(t *testing.T) {
	dir := t.TempDir()
	var inside, maxHeld int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := WithLock(context.Background(), dir, "k", func() error {
				mu.Lock()
				inside++
				if inside > maxHeld {
					maxHeld = inside
				}
				mu.Unlock()
				time.Sleep(10 * time.Millisecond)
				mu.Lock()
				inside--
				mu.Unlock()
				return nil
			})
			assert.NoError(t, err) //nolint:testifylint // goroutine: require would FailNow off the test goroutine
		}()
	}
	wg.Wait()
	assert.Equal(t, 1, maxHeld, "lock allowed concurrent holders")
}
