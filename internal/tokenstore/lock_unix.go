//go:build unix

package tokenstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Lock takes an exclusive cross-process lock for profile (flock on a lock
// file under Dir), waiting until it is free or ctx is done. Refresh tokens
// are single-use, so tmi-mcp processes sharing a profile must not refresh
// at the same time. Call the returned func to release it.
func (s *Store) Lock(ctx context.Context, profile string) (func(), error) {
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(s.Dir, profile+".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { _ = f.Close() }, nil // closing releases the lock
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, err
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
