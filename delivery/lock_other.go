//go:build !unix

package delivery

// Lock is the exclusive lock of one service; it needs flock, so only unix.
type Lock struct{}

// AcquireLock reports ErrUnsupported off unix.
func AcquireLock(base, service string) (*Lock, error) { return nil, ErrUnsupported }

// Close does nothing.
func (l *Lock) Close() error { return nil }
