//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

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
	return lockFile(p)
}

// AcquireUIDLock takes the lock of one target user under base, or returns
// ErrBusy: a delivery owns its user exclusively, and this is what makes it a
// property between instances (two services of one user, a delivery that is
// tearing down while another starts), whatever --base each of them was given.
// The caller passes the one fixed base. The helper inherits the descriptor.
func AcquireUIDLock(base string, uid int) (*Lock, error) {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return nil, err
	}
	return lockFile(UIDLockPath(base, uid))
}

// TeardownWait is how long a start waits for the lock of its own service to be
// free: the helper of a run that just ended holds it until it has killed the
// user's processes and unmounted, which takes up to 20 s (root kill budget) plus
// 1 s plus 5 s, so 30 s covers it. A lock that is still held after that is a run
// that is alive, and the start is refused (ErrBusy).
const TeardownWait = 30 * time.Second

// UIDLockGrace is how long a start waits for the lock of the user once it holds
// the lock of its service: the helper of the previous run of the same service
// drops both together, so only the instant between the two closes is covered.
// A user held by ANOTHER service stays refused: it is a user decision that a
// user belongs to one service.
const UIDLockGrace = 500 * time.Millisecond

// lockPoll is the pause between two attempts of a wait.
const lockPoll = 50 * time.Millisecond

// waitFor retries try while it reports ErrBusy, for at most wait.
func waitFor(wait time.Duration, try func() (*Lock, error)) (*Lock, error) {
	deadline := time.Now().Add(wait)
	for {
		l, err := try()
		if err == nil || !errors.Is(err, ErrBusy) || !time.Now().Before(deadline) {
			return l, err
		}
		time.Sleep(lockPoll)
	}
}

// AcquireLockWait is AcquireLock that waits up to wait for a lock held by a
// teardown in progress; it returns ErrBusy when the lock is still held then.
func AcquireLockWait(base, service string, wait time.Duration) (*Lock, error) {
	return waitFor(wait, func() (*Lock, error) { return AcquireLock(base, service) })
}

// AcquireUIDLockWait is AcquireUIDLock that waits up to wait.
func AcquireUIDLockWait(base string, uid int, wait time.Duration) (*Lock, error) {
	return waitFor(wait, func() (*Lock, error) { return AcquireUIDLock(base, uid) })
}

func lockFile(p string) (*Lock, error) {
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

// file is the descriptor that holds the lock, for a child to inherit; nil once
// the lock is closed.
func (l *Lock) file() *os.File {
	if l == nil {
		return nil
	}
	return l.f
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
