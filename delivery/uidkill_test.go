//go:build unix

package delivery

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeTable is a scripted process table: a process listed under the uid stays
// until it is sent SIGKILL, unless protect says it defends itself, and the
// table can grow (a forking program) while its processes are not stopped.
type fakeTable struct {
	live      map[int]bool
	stopped   map[int]bool
	sent      []string
	clock     time.Time
	forkEvery int // each list call adds a process while any is running
	nextPID   int
	protect   map[int]int // pid -> SIGKILLs it survives
	listErr   error
	sigErr    error
}

func newTable(pids ...int) *fakeTable {
	f := &fakeTable{live: map[int]bool{}, stopped: map[int]bool{}, clock: time.Unix(1000, 0), nextPID: 1000, protect: map[int]int{}}
	for _, p := range pids {
		f.live[p] = true
	}
	return f
}

func (f *fakeTable) ops() procOps {
	return procOps{
		list: func(uid int) ([]int, error) {
			if f.listErr != nil {
				return nil, f.listErr
			}
			// A loop that ignores its budget ends here with an error, so a
			// mutant that never gives up fails a test instead of hanging it.
			if f.clock.After(time.Unix(1000, 0).Add(2 * rootKillBudget)) {
				return nil, errors.New("fake: the clock ran past twice the budget")
			}
			if f.forkEvery > 0 {
				for p := range f.live {
					if !f.stopped[p] {
						f.nextPID++
						f.live[f.nextPID] = true
						break
					}
				}
			}
			var out []int
			for p := range f.live {
				out = append(out, p)
			}
			return out, nil
		},
		signal: func(pid int, sig syscall.Signal) error {
			f.sent = append(f.sent, sigName(sig)+":"+itoa(pid))
			if f.sigErr != nil {
				return f.sigErr
			}
			if !f.live[pid] {
				return unix.ESRCH
			}
			switch sig {
			case unix.SIGSTOP:
				f.stopped[pid] = true
			case unix.SIGKILL:
				if f.protect[pid] > 0 {
					f.protect[pid]--
					return nil
				}
				delete(f.live, pid)
			}
			return nil
		},
		sleep: func(d time.Duration) { f.clock = f.clock.Add(d) },
		now:   func() time.Time { return f.clock },
	}
}

func sigName(s syscall.Signal) string {
	switch s {
	case unix.SIGSTOP:
		return "STOP"
	case unix.SIGKILL:
		return "KILL"
	}
	return "?"
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestKillAllOfEmptiesTheTable(t *testing.T) {
	f := newTable(10, 11, 12)
	if err := killAllOf(5000, f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.live) != 0 {
		t.Fatalf("left %v", f.live)
	}
	// Everything is stopped before the first kill: a process that is stopped
	// cannot kill the others or fork.
	firstKill := slices.IndexFunc(f.sent, func(s string) bool { return strings.HasPrefix(s, "KILL") })
	stops := 0
	for _, s := range f.sent[:firstKill] {
		if strings.HasPrefix(s, "STOP") {
			stops++
		}
	}
	if firstKill < 0 || stops < 3 {
		t.Fatalf("sent %v: want every process stopped before the first kill", f.sent)
	}
}

func TestKillAllOfNothingToDo(t *testing.T) {
	f := newTable()
	if err := killAllOf(5000, f.ops()); err != nil || len(f.sent) != 0 {
		t.Fatalf("%v %v", err, f.sent)
	}
}

// A process that survives the first SIGKILLs is signalled again, until it goes.
func TestKillAllOfRepeatsUntilGone(t *testing.T) {
	f := newTable(10)
	f.protect[10] = 3
	if err := killAllOf(5000, f.ops()); err != nil {
		t.Fatal(err)
	}
	kills := 0
	for _, s := range f.sent {
		if s == "KILL:10" {
			kills++
		}
	}
	if kills != 4 {
		t.Fatalf("%d SIGKILLs, want 4 (%v)", kills, f.sent)
	}
}

// A program that forks as fast as the table is read is frozen before it is
// killed: the table settles, then empties.
func TestKillAllOfCatchesWhatForks(t *testing.T) {
	f := newTable(10)
	f.forkEvery = 1
	err := killAllOf(5000, f.ops())
	f.forkEvery = 0
	if err != nil {
		t.Fatal(err)
	}
	if len(f.live) != 0 {
		t.Fatalf("left %v", f.live)
	}
}

// What cannot be killed is an error, after the budget, never a quiet success.
func TestKillAllOfReportsSurvivors(t *testing.T) {
	f := newTable(10)
	f.protect[10] = 1 << 30
	start := f.clock
	// A loop that never gives up must fail here, not hang the suite.
	bounded := func() procOps {
		o := f.ops()
		inner := o.sleep
		o.sleep = func(d time.Duration) {
			inner(d)
			if f.clock.Sub(start) > 2*rootKillBudget {
				t.Fatal("killAllOf did not give up at its budget")
			}
		}
		return o
	}
	err := killAllOf(5000, bounded())
	if !errors.Is(err, ErrUIDSurvives) {
		t.Fatalf("got %v", err)
	}
	if got := f.clock.Sub(start); got < rootKillBudget || got > rootKillBudget+time.Second {
		t.Fatalf("gave up after %v, budget %v", got, rootKillBudget)
	}
	f.sigErr = unix.EPERM
	start = f.clock
	if err := killAllOf(5000, bounded()); !errors.Is(err, ErrUIDSurvives) || !errors.Is(err, unix.EPERM) {
		t.Fatalf("a signal that failed is part of the error: %v", err)
	}
}

func TestKillAllOfTableErrors(t *testing.T) {
	boom := errors.New("boom")
	f := newTable(10)
	f.listErr = boom
	if err := killAllOf(5000, f.ops()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	// An error on the second read, inside the freeze.
	calls := 0
	o := newTable(10).ops()
	inner := o.list
	o.list = func(uid int) ([]int, error) {
		calls++
		if calls == 2 {
			return nil, boom
		}
		return inner(uid)
	}
	if err := killAllOf(5000, o); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	for _, uid := range []int{0, -1, 1 << 40} {
		if err := killAllOf(uid, newTable(10).ops()); err == nil {
			t.Fatalf("uid %d accepted", uid)
		}
	}
}

// pid 1, pid 0 and this process are never signalled, whatever the table says.
func TestKillAllOfNeverSignalsInitOrItself(t *testing.T) {
	f := newTable(0, 1, os.Getpid(), 10)
	_ = killAllOf(5000, f.ops())
	for _, s := range f.sent {
		for _, bad := range []string{":0", ":1", ":" + itoa(os.Getpid())} {
			if strings.HasSuffix(s, bad) {
				t.Fatalf("signalled %s", s)
			}
		}
	}
}

func TestSameSet(t *testing.T) {
	if !sameSet([]int{3, 1, 2}, []int{1, 2, 3}) || sameSet([]int{1}, []int{1, 2}) || sameSet([]int{1, 2}, []int{1, 3}) {
		t.Fatal("sameSet")
	}
	a := []int{2, 1}
	sameSet(a, []int{1, 2})
	if a[0] != 2 {
		t.Fatal("sameSet sorted its argument")
	}
}

func TestOnlyProcessAndBusy(t *testing.T) {
	f := newTable(10)
	if err := onlyProcess(5000, 10, f.ops()); err != nil {
		t.Fatal(err)
	}
	f.live[11] = true
	if err := onlyProcess(5000, 10, f.ops()); !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("got %v", err)
	}
	if err := onlyProcess(5000, 99, f.ops()); !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("the program is not the process listed: %v", err)
	}
	f.listErr = errors.New("boom")
	if err := onlyProcess(5000, 10, f.ops()); err == nil || errors.Is(err, ErrUIDBusy) {
		t.Fatalf("got %v", err)
	}
	if _, err := busyOf(5000, f.ops()); err == nil {
		t.Fatal("busyOf swallowed the error")
	}
	f.listErr = nil
	if b, err := busyOf(5000, f.ops()); err != nil || !b {
		t.Fatalf("%v %v", b, err)
	}
	if b, err := busyOf(5000, newTable().ops()); err != nil || b {
		t.Fatalf("%v %v", b, err)
	}
}

// The user lock is exclusive between instances whatever their service (R2).
func TestAcquireUIDLock(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	l, err := AcquireUIDLock(root, 32001)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireUIDLock(root, 32001); !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock of the same user: %v", err)
	}
	other, err := AcquireUIDLock(root, 32002)
	if err != nil {
		t.Fatalf("another user must not be blocked: %v", err)
	}
	other.Close()
	// A service lock is another lock: neither blocks the other.
	s, err := AcquireLock(root, "svc")
	if err != nil {
		t.Fatalf("a service lock is not a user lock: %v", err)
	}
	s.Close()
	l.Close()
	l, err = AcquireUIDLock(root, 32001)
	if err != nil {
		t.Fatalf("after Close: %v", err)
	}
	l.Close()
	for _, uid := range []int{0, -1, 1 << 32, 0xFFFFFFFF} {
		if _, err := AcquireUIDLock(root, uid); err == nil {
			t.Fatalf("uid %d accepted", uid)
		}
	}
	if got := filepath.Base(UIDLockPath(root, 32001)); got != ".uid-32001.lock" {
		t.Fatalf("lock name %q", got)
	}
}

// A nil delivery or lock is safe to hand around: each answers with its zero value.
func TestNilDeliveryAndLockAreSafe(t *testing.T) {
	// Each case is judged by an assertion, not by whether it crashes: a crash
	// would otherwise end the test binary and hide the cases after it.
	check := func(name string, f func() bool) {
		t.Helper()
		ok := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: a nil receiver was not refused", name)
				}
			}()
			ok = f()
		}()
		if !ok {
			t.Errorf("%s: wrong answer", name)
		}
	}
	var d *Delivery
	check("Release of nil", func() bool { return d.Release() == nil })
	check("Lost of nil", func() bool { return d.Lost() == nil })
	check("Lost without a helper", func() bool { return (&Delivery{}).Lost() == nil })
	check("Release without a helper", func() bool { return (&Delivery{}).Release() == nil })
	var l *Lock
	check("file of a nil lock", func() bool { return l.file() == nil })
	check("Close of a nil lock", func() bool { return l.Close() == nil })
}
