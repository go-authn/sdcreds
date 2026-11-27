//go:build unix

package delivery

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// fakeTable is a scripted process table with a scripted killer: a process listed
// under the uid stays until a killer that reaches it has run, unless it is
// unreachable (the killer finds nothing to signal) or protected (it survives some
// passes). The table can grow (a forking program) between passes.
type fakeTable struct {
	live        map[int]bool
	clock       time.Time
	forkEvery   int // each killer pass leaves this many new processes
	nextPID     int
	protect     map[int]int // pid -> killer passes it survives
	unreachable map[int]bool
	listErr     error
	killErr     error
	exit        int // exit status of every killer; 0 when unset
	passes      int
	budgets     []time.Duration
	listed      []int
}

func (f *fakeTable) listAll() ([]proc, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	// A loop that ignores its budget ends here with an error, so a
	// mutant that never gives up fails a test instead of hanging it.
	if f.clock.After(time.Unix(1000, 0).Add(2 * rootKillBudget)) {
		return nil, errors.New("fake: the clock ran past twice the budget")
	}
	var out []proc
	for p := range f.live {
		out = append(out, proc{pid: p})
	}
	return out, nil
}

func newTable(pids ...int) *fakeTable {
	f := &fakeTable{live: map[int]bool{}, clock: time.Unix(1000, 0), nextPID: 1000, protect: map[int]int{}, unreachable: map[int]bool{}}
	for _, p := range pids {
		f.live[p] = true
	}
	return f
}

func (f *fakeTable) ops() procOps {
	return procOps{
		list: func(uid int) ([]proc, error) { f.listed = append(f.listed, uid); return f.listAll() },
		kill: func(wait time.Duration) (int, error) {
			f.passes++
			f.budgets = append(f.budgets, wait)
			for p := range f.live {
				switch {
				case f.unreachable[p]:
				case f.protect[p] > 0:
					f.protect[p]--
				default:
					delete(f.live, p)
				}
			}
			for i := 0; i < f.forkEvery; i++ {
				f.nextPID++
				f.live[f.nextPID] = true
			}
			if f.killErr != nil {
				return -1, f.killErr
			}
			return f.exit, nil
		},
		sleep: func(d time.Duration) { f.clock = f.clock.Add(d) },
		now:   func() time.Time { return f.clock },
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func TestKillAllOfEmptiesTheTable(t *testing.T) {
	f := newTable(10, 11, 12)
	if err := killAllOf(5000, f.ops()); err != nil {
		t.Fatal(err)
	}
	if len(f.live) != 0 || f.passes != 1 {
		t.Fatalf("left %v after %d pass(es)", f.live, f.passes)
	}
	if f.budgets[0] != rootKillBudget {
		t.Fatalf("the killer was given %v, want the whole budget", f.budgets[0])
	}
}

func TestKillAllOfNothingToDo(t *testing.T) {
	f := newTable()
	if err := killAllOf(5000, f.ops()); err != nil || f.passes != 0 {
		t.Fatalf("%v, %d pass(es)", err, f.passes)
	}
}

// A process that survives a pass is dealt with by the next one, until it goes;
// the budget handed to a killer shrinks as the time goes.
func TestKillAllOfRepeatsUntilGone(t *testing.T) {
	f := newTable(10)
	f.protect[10] = 3
	if err := killAllOf(5000, f.ops()); err != nil {
		t.Fatal(err)
	}
	if f.passes != 4 {
		t.Fatalf("%d passes, want 4", f.passes)
	}
	if !(f.budgets[3] < f.budgets[0]) {
		t.Fatalf("budgets %v: the time spent is not taken off", f.budgets)
	}
}

// A program that forks between passes is caught by the next pass.
func TestKillAllOfCatchesWhatForks(t *testing.T) {
	f := newTable(10)
	f.forkEvery = 2
	o := f.ops()
	inner := o.kill
	o.kill = func(w time.Duration) (int, error) {
		code, err := inner(w)
		if f.passes == 3 {
			f.forkEvery = 0 // the program is done forking
		}
		return code, err
	}
	if err := killAllOf(5000, o); err != nil {
		t.Fatal(err)
	}
	if len(f.live) != 0 {
		t.Fatalf("left %v", f.live)
	}
}

// What cannot be reached is an error, after the budget, never a quiet success:
// this is a process that holds the user only as a set-id program (its credentials
// are not the killer's reach).
func TestKillAllOfReportsSurvivors(t *testing.T) {
	f := newTable(10)
	f.unreachable[10] = true
	start := f.clock
	err := killAllOf(5000, f.ops())
	if !errors.Is(err, ErrUIDSurvives) {
		t.Fatalf("got %v", err)
	}
	if got := f.clock.Sub(start); got < rootKillBudget || got > rootKillBudget+time.Second {
		t.Fatalf("gave up after %v, budget %v", got, rootKillBudget)
	}
	// A killer that failed is part of the error.
	f = newTable(10)
	f.unreachable[10] = true
	f.killErr = unix.EPERM
	if err := killAllOf(5000, f.ops()); !errors.Is(err, ErrUIDSurvives) || !errors.Is(err, unix.EPERM) {
		t.Fatalf("a killer that failed is part of the error: %v", err)
	}
}

// A killer that was refused (not root, wrong ids) or could not take its
// credentials is not run again: the next pass would be the same.
func TestKillAllOfStopsOnARefusedKiller(t *testing.T) {
	for _, code := range []int{killExitUsage, killExitCreds} {
		f := newTable(10)
		f.exit = code
		if err := killAllOf(5000, f.ops()); !errors.Is(err, ErrKiller) || f.passes != 1 {
			t.Fatalf("exit %d: %v after %d pass(es)", code, err, f.passes)
		}
	}
	// Exit 4 (survivors) and a killer that died are run again.
	f := newTable(10)
	f.exit = killExitSurvives
	f.protect[10] = 1
	if err := killAllOf(5000, f.ops()); err != nil || f.passes != 2 {
		t.Fatalf("%v after %d pass(es)", err, f.passes)
	}
}

func TestKillAllOfTableErrors(t *testing.T) {
	boom := errors.New("boom")
	f := newTable(10)
	f.listErr = boom
	if err := killAllOf(5000, f.ops()); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	// An error on the second read, after a pass.
	calls := 0
	o := newTable(10).ops()
	o.kill = func(time.Duration) (int, error) { return 0, nil }
	inner := o.list
	o.list = func(uid int) ([]proc, error) {
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

// F5 and F4: the release is judged by the same set as the start check (real,
// effective or saved uid), so a process that holds the uid by any of the three
// and is not gone keeps the release from reporting success.
func TestKillAllOfIsJudgedByTheStartCheckSet(t *testing.T) {
	f := newTable(10, 11, 12) // 11, 12: effective-only and saved-only holders
	o := f.ops()
	if err := killAllOf(5000, o); err != nil {
		t.Fatal(err)
	}
	if b, err := busyOf(5000, o); err != nil || b {
		t.Fatalf("after the release the start check must pass: %v %v", b, err)
	}
	f = newTable(10, 11)
	f.unreachable[11] = true
	if err := killAllOf(5000, f.ops()); !errors.Is(err, ErrUIDSurvives) {
		t.Fatalf("a holder the killer does not reach must be reported: %v", err)
	}
}

func TestParseKillArgs(t *testing.T) {
	uid, k, g, err := parseKillArgs([]string{"kill", "32001", "32100", "32101"})
	if err != nil || uid != 32001 || k != 32100 || g != 32101 {
		t.Fatalf("%d %d %d %v", uid, k, g, err)
	}
	for name, args := range map[string][]string{
		"no arguments":          nil,
		"old form":              {"kill"},
		"another command":       {"stop", "1", "2", "3"},
		"too many":              {"kill", "1", "2", "3", "4"},
		"target is root":        {"kill", "0", "32100", "32101"},
		"killer is root":        {"kill", "32001", "0", "32101"},
		"killer is the target":  {"kill", "32001", "32001", "32101"},
		"not a number":          {"kill", "32001", "x", "32101"},
		"negative":              {"kill", "32001", "-5", "32101"},
		"beyond 32 bits":        {"kill", "32001", "4294967296", "32101"},
		"gid is root":           {"kill", "32001", "32100", "0"},
		"empty":                 {"kill", "", "32100", "32101"},
		"trailing garbage":      {"kill", "32001", "32100", "32101x"},
		"all ones":              {"kill", "32001", "4294967295", "32101"},
		"target of the killer?": {"kill", "32100", "32100", "32100"},
	} {
		func() {
			// A panic on a short list is a refusal that is not made: a failure.
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%s: panic %v", name, r)
				}
			}()
			if _, _, _, err := parseKillArgs(args); err == nil {
				t.Errorf("%s: accepted", name)
			}
		}()
	}
	if _, _, _, err := parseKillArgs([]string{"kill", "32001", "32100"}); err == nil {
		t.Error("too few: accepted")
	}
	// A word and a number out of range are told apart from the ids that are refused.
	if _, _, _, err := parseKillArgs([]string{"kill", "32001", "x", "32101"}); err == nil || !strings.Contains(err.Error(), "not an id") {
		t.Errorf("a word: %v, want %q", err, "not an id")
	}
}

func TestCheckKiller(t *testing.T) {
	none := func(int) ([]proc, error) { return nil, nil }
	if err := checkKiller(32001, 32100, none); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		uid, killer int
		list        func(int) ([]proc, error)
	}{
		"root":               {32001, 0, none},
		"the target":         {32001, 32001, none},
		"owns a process":     {32001, 32100, func(int) ([]proc, error) { return []proc{{pid: 7}}, nil }},
		"table not readable": {32001, 32100, func(int) ([]proc, error) { return nil, errors.New("boom") }},
	} {
		if err := checkKiller(c.uid, c.killer, c.list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := checkKiller(32001, 0, none); !errors.Is(err, ErrKiller) {
		t.Errorf("root: %v", err)
	}
	if err := checkKiller(32001, 32100, func(int) ([]proc, error) { return []proc{{pid: 7}}, nil }); !errors.Is(err, ErrKiller) {
		t.Errorf("owns a process: %v", err)
	}
}

// The killers of a machine go one at a time: the lock is exclusive, is waited
// for within a bound, and is a private plain file.
func TestLockKiller(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "killer.lock")
	l, err := lockKiller(p, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Now()
	// Bounded here, so that a wait that never ends is a failure, not a hang.
	res := make(chan error, 1)
	go func() { _, err := lockKiller(p, 200*time.Millisecond); res <- err }()
	select {
	case err := <-res:
		if !errors.Is(err, ErrBusy) || time.Since(t0) < 150*time.Millisecond {
			t.Fatalf("second killer: %v after %v", err, time.Since(t0))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait for the killer lock does not end at its bound")
	}
	// Released during the wait: the second one goes on.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); time.Sleep(100 * time.Millisecond); l.Close() }()
	l2, err := lockKiller(p, 5*time.Second)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	wg.Wait()
	l2.Close()
	// Not a private plain file of this user: refused.
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := lockKiller(p, 0); err == nil {
		t.Fatal("a world-writable lock file accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, err := lockKiller(link, 0); err == nil {
		t.Fatal("a symbolic link accepted")
	}
	if _, err := lockKiller(filepath.Join(dir, "absent", "x"), 0); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("a missing directory: %v, want the open error itself", err)
	}
}

// F4: the release signals nothing by pid. No non-test file of the module calls
// unix.Kill or syscall.Kill with anything but the literal -1 (kill(-1) is the
// kernel walking its own table), and none looks a process up by pid.
func TestNoSignalIsAddressedByPid(t *testing.T) {
	fset := token.NewFileSet()
	var seen int
	for _, dir := range []string{".", "../cmd/sdcreds", "../s6", ".."} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, name, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			seen++
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				pos := fset.Position(call.Pos())
				switch {
				case (pkg.Name == "unix" || pkg.Name == "syscall") && sel.Sel.Name == "Kill":
					if !isMinusOne(call.Args) {
						t.Errorf("%s: %s.Kill with a pid argument that is not the literal -1", pos, pkg.Name)
					}
				case pkg.Name == "os" && sel.Sel.Name == "FindProcess":
					t.Errorf("%s: os.FindProcess: a process looked up by pid", pos)
				}
				return true
			})
		}
	}
	if seen < 10 {
		t.Fatalf("read %d source files: the gate looked in the wrong place", seen)
	}
}

func isMinusOne(args []ast.Expr) bool {
	if len(args) == 0 {
		return false
	}
	u, ok := args[0].(*ast.UnaryExpr)
	if !ok || u.Op != token.SUB {
		return false
	}
	lit, ok := u.X.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "1"
}

// The gate itself: it sees a signal addressed by pid.
func TestIsMinusOne(t *testing.T) {
	parse := func(src string) []ast.Expr {
		e, err := parser.ParseExpr("f(" + src + ")")
		if err != nil {
			t.Fatal(err)
		}
		return e.(*ast.CallExpr).Args
	}
	if !isMinusOne(parse("-1, sig")) {
		t.Error("-1 refused")
	}
	for _, bad := range []string{"pid, sig", "1, sig", "-2, sig", "-pid, sig", "+1, sig", "0, sig"} {
		if isMinusOne(parse(bad)) {
			t.Errorf("%q accepted", bad)
		}
	}
	if isMinusOne(nil) {
		t.Error("no arguments accepted")
	}
}

// T5: an empty table does not show the program, so it is not "alone".
func TestOnlyProcessRefusesAnEmptyTable(t *testing.T) {
	if err := onlyProcess(5000, 10, newTable().ops()); !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("got %v", err)
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
