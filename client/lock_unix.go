//go:build unix

package client

import (
	"os"
	"syscall"
)

// lockFile takes an exclusive advisory lock on path (created 0600), so two processes sharing a parent file
// cannot both present the same parent (which Warden would treat as reuse and revoke the family).
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: the configured parent file's lock
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { //nolint:gosec // G115: fd fits in int
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) //nolint:gosec // G115: fd fits in int
		_ = f.Close()
	}, nil
}
