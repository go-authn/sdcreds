//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// procOps is what the root-side kill needs from the system; the tests give it a
// scripted process table.
type procOps struct {
	// list returns the pids whose real or effective uid is uid.
	list   func(uid int) ([]int, error)
	signal func(pid int, sig syscall.Signal) error
	sleep  func(time.Duration)
	now    func() time.Time
}

const (
	// rootKillBudget is how long root keeps trying: a process that is not gone by
	// then is in a state SIGKILL does not reach, and the caller is told.
	rootKillBudget = 20 * time.Second
	// stopPasses bounds the freeze: processes that are stopped cannot fork, so the
	// list settles; a table that never does is killed as it stands.
	stopPasses = 16
	killPause  = 5 * time.Millisecond
)

// killAllOf makes every process of uid go, signalled by the caller itself (root):
// a process of the target cannot signal root, so none of them can stop this. It
// stops everything it finds, reads the table again until a pass finds nothing
// new (a stopped process cannot fork or kill), then sends SIGKILL, and goes on
// until the table is empty. It returns ErrUIDSurvives if time runs out first.
func killAllOf(uid int, o procOps) error {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return err
	}
	deadline := o.now().Add(rootKillBudget)
	var sigErr error
	send := func(pids []int, sig syscall.Signal) {
		for _, p := range pids {
			// pid 0 and 1 are never signalled whatever the table says; ESRCH is the
			// process having already gone.
			if p <= 1 || p == os.Getpid() {
				continue
			}
			if err := o.signal(p, sig); err != nil && !errors.Is(err, unix.ESRCH) {
				sigErr = err
			}
		}
	}
	for {
		pids, err := o.list(uid)
		if err != nil {
			return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
		}
		if len(pids) == 0 {
			return nil
		}
		for pass := 0; pass < stopPasses; pass++ {
			send(pids, unix.SIGSTOP)
			again, err := o.list(uid)
			if err != nil {
				return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
			}
			settled := sameSet(pids, again)
			pids = again
			if settled {
				break
			}
		}
		send(pids, unix.SIGKILL)
		if !o.now().Before(deadline) {
			err := fmt.Errorf("%w (uid %d)", ErrUIDSurvives, uid)
			if sigErr != nil {
				err = errors.Join(err, sigErr)
			}
			return err
		}
		o.sleep(killPause)
	}
}

func sameSet(a, b []int) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// onlyProcess reports ErrUIDBusy unless pid is the one process of uid.
func onlyProcess(uid, pid int, o procOps) error {
	pids, err := o.list(uid)
	if err != nil {
		return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
	}
	for _, p := range pids {
		if p != pid {
			return fmt.Errorf("%w: uid %d has process %d besides the program", ErrUIDBusy, uid, p)
		}
	}
	return nil
}

// busyOf reports whether uid has any process.
func busyOf(uid int, o procOps) (bool, error) {
	pids, err := o.list(uid)
	if err != nil {
		return false, fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
	}
	return len(pids) > 0, nil
}
