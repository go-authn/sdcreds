//go:build unix

package delivery

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// A release never skips the kill of its own user because the kill of ANOTHER user
// is slow: user A's killer is stuck, and the release of user B, which asks for
// its lock with a short wait, still kills. With one global lock B was refused
// (ErrBusy) and killed nothing.
func TestTwoReleasesBothKillWhileOneIsStuck(t *testing.T) {
	old := killerLockBase
	killerLockBase = filepath.Join(t.TempDir(), "killer")
	defer func() { killerLockBase = old }()
	const uidA, uidB = 5001, 5002
	if killerLockFile(uidA) == killerLockFile(uidB) {
		t.Fatal("two users share one killer lock")
	}
	fa, fb := newTable(10, 11), newTable(20, 21)
	oa := fa.ops()
	inner := oa.kill
	started, gate := make(chan struct{}), make(chan struct{})
	oa.kill = func(w time.Duration) (int, error) {
		close(started)
		<-gate
		return inner(w)
	}
	resA := make(chan error, 1)
	go func() { resA <- killLocked(uidA, killerLockFile(uidA), 200*time.Millisecond, oa) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the first release did not start")
	}
	if err := killLocked(uidB, killerLockFile(uidB), 200*time.Millisecond, fb.ops()); err != nil {
		t.Fatalf("the second release, while the first is stuck: %v", err)
	}
	if len(fb.live) != 0 || fb.passes != 1 {
		t.Fatalf("the second release left %v after %d pass(es)", fb.live, fb.passes)
	}
	// The same user is still exclusive: a second kill of A waits, then is refused.
	if err := killLocked(uidA, killerLockFile(uidA), 100*time.Millisecond, fa.ops()); !errors.Is(err, ErrBusy) {
		t.Fatalf("a second kill of the same user: %v", err)
	}
	close(gate)
	if err := <-resA; err != nil || len(fa.live) != 0 {
		t.Fatalf("the first release: %v, left %v", err, fa.live)
	}
}

// The start refuses a killer user that owns a process, but waits out the killer
// of a release of another user that is running at that moment; root and the
// target are never waited for.
func TestCheckKillerAtStart(t *testing.T) {
	clock := time.Unix(1000, 0)
	mk := func(owned func() bool) procOps {
		return procOps{
			list: func(uid int) ([]proc, error) {
				if uid == 32100 && owned() {
					return []proc{{pid: 7}}, nil
				}
				return nil, nil
			},
			sleep: func(d time.Duration) {
				clock = clock.Add(d)
				// A loop that never gives up ends here, not in a hang.
				if clock.After(time.Unix(1000, 0).Add(3 * rootKillBudget)) {
					t.Fatalf("the wait for the killer user never ends")
				}
			},
			now: func() time.Time { return clock },
		}
	}
	// A release ends during the wait: accepted.
	if err := checkKillerAtStart(32001, 32100, rootKillBudget, mk(func() bool { return clock.Before(time.Unix(1005, 0)) })); err != nil {
		t.Fatalf("a killer of a running release: %v", err)
	}
	// A killer user that owns a process for good: refused, after the wait.
	clock = time.Unix(1000, 0)
	if err := checkKillerAtStart(32001, 32100, rootKillBudget, mk(func() bool { return true })); !errors.Is(err, ErrKiller) {
		t.Fatalf("a killer that owns a process: %v", err)
	}
	if clock.Sub(time.Unix(1000, 0)) < rootKillBudget {
		t.Fatalf("refused after %v, before the wait ended", clock.Sub(time.Unix(1000, 0)))
	}
	// Root and the target: at once.
	clock = time.Unix(1000, 0)
	for _, k := range []int{0, 32001} {
		if err := checkKillerAtStart(32001, k, rootKillBudget, mk(func() bool { return false })); !errors.Is(err, ErrKiller) || !clock.Equal(time.Unix(1000, 0)) {
			t.Errorf("killer %d: %v", k, err)
		}
	}
}
