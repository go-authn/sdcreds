//go:build unix

package exitguard

import (
	"errors"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// The deadline fires in the window after the child has been reaped and before
// the standard library has marked it done (os/exec_unix.go: Wait4 returns, then
// doRelease(statusDone); the window os/wait_unimp.go describes for OpenBSD). The
// window is forced by a reap that stays there for 50ms, and the exit is observed
// by a fake watch. No kill may follow the reap.
func TestNoKillFollowsTheReap(t *testing.T) {
	var reaped atomic.Bool
	var killsAfterReap, kills atomic.Int32
	watch := func(pid int) (<-chan struct{}, error) {
		exited := make(chan struct{})
		go func() {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			time.Sleep(10 * time.Millisecond)
			close(exited)
		}()
		return exited, nil
	}
	kill := func(p *os.Process) error {
		kills.Add(1)
		if reaped.Load() {
			killsAfterReap.Add(1)
		}
		return p.Kill()
	}
	reap := func(c *exec.Cmd) error {
		err := c.Wait()
		reaped.Store(true)
		time.Sleep(50 * time.Millisecond) // the pid is free, os has not noticed
		return err
	}
	c := exec.Command("sleep", "60")
	// 30ms: after the exit is observed (10ms), inside the reap's window.
	err := run(c, 30*time.Millisecond, watch, kill, reap)
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("want the exit of the killed child: %v", err)
	}
	if n := killsAfterReap.Load(); n != 0 {
		t.Fatalf("%d kill(s) were sent after the reap", n)
	}
	if kills.Load() != 0 {
		t.Fatalf("a kill was sent although the child had already exited")
	}
}

// A child that outlives the deadline is killed, once, while it runs.
func TestARunningChildIsKilledAtTheDeadline(t *testing.T) {
	var kills atomic.Int32
	killed := make(chan struct{})
	watch := func(int) (<-chan struct{}, error) {
		exited := make(chan struct{})
		go func() {
			<-killed // the exit is observed once the kill was sent
			time.Sleep(10 * time.Millisecond)
			close(exited)
		}()
		return exited, nil
	}
	kill := func(p *os.Process) error { kills.Add(1); close(killed); return p.Kill() }
	start := time.Now()
	err := run(exec.Command("sleep", "60"), 50*time.Millisecond, watch, kill, (*exec.Cmd).Wait)
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != -1 {
		t.Fatalf("want a child killed by a signal: %v", err)
	}
	if kills.Load() != 1 {
		t.Fatalf("%d kills", kills.Load())
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}

// A watch that fails kills and reaps the child, and reports the failure.
func TestAFailedWatchKillsTheChild(t *testing.T) {
	boom := errors.New("boom")
	var killed atomic.Bool
	err := run(exec.Command("sleep", "60"), time.Minute,
		func(int) (<-chan struct{}, error) { return nil, boom },
		func(p *os.Process) error { killed.Store(true); return p.Kill() },
		(*exec.Cmd).Wait)
	if !errors.Is(err, boom) || !killed.Load() {
		t.Fatalf("%v killed=%v", err, killed.Load())
	}
}
