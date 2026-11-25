//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// Lock is the exclusive lock of one service: flock(LOCK_EX|LOCK_NB) on
// Base/.SERVICE.lock, held until Close or the death of the process, whatever
// kills it. The descriptor is close-on-exec: the service never holds it.
type Lock struct{ f *os.File }

// AcquireLock takes the lock of service under base, or returns ErrBusy without
// touching anything. base must exist and be trusted (see EnsureBase).
func AcquireLock(base, service string) (*Lock, error) {
	p, err := LockPath(base, service)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open(p, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}
	f := os.NewFile(uintptr(fd), p)
	var st unix.Stat_t
	if err := fstat(fd, &st); err != nil {
		f.Close()
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != trustedUID || st.Nlink != 1 || st.Mode&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("%w: %s is not a private regular file of root", ErrUntrustedPath, p)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("%w: %s", ErrBusy, p)
		}
		return nil, &os.PathError{Op: "flock", Path: p, Err: err}
	}
	return &Lock{f}, nil
}

// Close releases the lock; idempotent.
func (l *Lock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	return f.Close()
}
