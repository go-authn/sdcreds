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

// giveUpAfter runs f and returns true when it came back within d. When it did
// not, f is left running in its goroutine: the caller goes on without it. The
// first-move killer is started this way, because a hostile process of the target
// can SIGSTOP the killer between its setuid and its exec, and the parent's fork
// then blocks until root has killed that user's processes, which is what the
// caller does next.
func giveUpAfter(d time.Duration, f func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		f()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// procOps is what the root-side kill needs from the system; the tests give it a
// scripted process table.
type procOps struct {
	// list returns the live processes whose real, effective or saved uid is uid:
	// what makes a start refuse AND what the kill goes by, so that a process that
	// holds the user's rights by any of the three cannot outlive the release and
	// block the next start.
	list   func(uid int) ([]proc, error)
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
	send := func(ps []proc, sig syscall.Signal) {
		for _, pr := range ps {
			// pid 0 and 1 are never signalled whatever the table says; ESRCH is the
			// process having already gone.
			if pr.pid <= 1 || pr.pid == os.Getpid() {
				continue
			}
			if err := o.signal(pr.pid, sig); err != nil && !errors.Is(err, unix.ESRCH) {
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
			// A pid that was stopped and is not the same process of the user any
			// more (it exited and the pid was given to another process between the
			// list and the stop) is resumed: root must not leave a stranger stopped.
			var strangers []proc
			for _, p := range pids {
				if !containsProc(again, p) {
					strangers = append(strangers, p)
				}
			}
			send(strangers, unix.SIGCONT)
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

func containsProc(s []proc, p proc) bool { return slices.Contains(s, p) }

func sameSet(a, b []proc) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	less := func(x, y proc) int {
		if x.pid != y.pid {
			return x.pid - y.pid
		}
		switch {
		case x.start < y.start:
			return -1
		case x.start > y.start:
			return 1
		}
		return 0
	}
	slices.SortFunc(a, less)
	slices.SortFunc(b, less)
	return slices.Equal(a, b)
}

// onlyProcess reports ErrUIDBusy unless pid is the one process of uid, and is
// listed: an empty table is not the program being alone, it is a table that does
// not show the program, which a wrong layout would produce.
func onlyProcess(uid, pid int, o procOps) error {
	pids, err := o.list(uid)
	if err != nil {
		return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
	}
	found := false
	for _, p := range pids {
		if p.pid != pid {
			return fmt.Errorf("%w: uid %d has process %d besides the program", ErrUIDBusy, uid, p.pid)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%w: the process table of uid %d does not list the program (pid %d)", ErrUIDBusy, uid, pid)
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
