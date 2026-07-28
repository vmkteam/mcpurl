package oauth

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

// WithLock runs fn while holding the cross-process refresh lock for key.
// The file lock is used even with the keychain backend: it guards the
// refresh *operation*, not the storage (04-oauth.md).
func WithLock(ctx context.Context, lockDir, key string, fn func() error) error {
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		return err
	}
	fl := flock.New(filepath.Join(lockDir, key+".lock"))
	// TryLockContext returns false only together with a ctx error.
	if _, err := fl.TryLockContext(ctx, 100*time.Millisecond); err != nil {
		return err
	}
	defer fl.Unlock() //nolint:errcheck // process exit releases anyway
	return fn()
}
