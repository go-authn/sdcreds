package exitguard

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// Run with the real watch: a child that ends by itself is not killed and its
// status is returned; one that outlives the deadline is killed.
func TestRunWithTheRealWatch(t *testing.T) {
	if err := Run(exec.Command("true"), time.Minute); err != nil {
		t.Fatalf("a child that exits 0: %v", err)
	}
	err := Run(exec.Command("false"), time.Minute)
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != 1 {
		t.Fatalf("a child that exits 1: %v", err)
	}
	start := time.Now()
	err = Run(exec.Command("sleep", "60"), 200*time.Millisecond)
	if !errors.As(err, &ee) || ee.ExitCode() != -1 {
		t.Fatalf("a child past the deadline: %v", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("took %v", d)
	}
}

// The watch fires when the child exits, with nobody having reaped it: the zombie
// still holds the pid, so a signal sent by it cannot reach another process.
func TestWatchExitFiresBeforeTheReap(t *testing.T) {
	c := exec.Command("sleep", "60")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	exited, err := WatchExit(c.Process.Pid)
	if err != nil {
		_ = c.Process.Kill()
		_ = c.Wait()
		t.Fatal(err)
	}
	select {
	case <-exited:
		t.Fatal("fired while the child runs")
	case <-time.After(200 * time.Millisecond):
	}
	_ = syscall.Kill(c.Process.Pid, syscall.SIGKILL)
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		_ = c.Wait()
		t.Fatal("no exit observed")
	}
	// Observed with nobody having waited: the exit status is still there to reap.
	if err := c.Wait(); err == nil {
		t.Fatal("a killed child reaped as a success")
	}
}
