package main

import (
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// The watch fires when the child exits, with nobody having reaped it: the zombie
// still holds the pid, so a signal sent by it cannot reach another process.
func TestWatchExitFiresBeforeTheReap(t *testing.T) {
	c := exec.Command("sleep", "60")
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	exited, err := watchExit(c.Process.Pid)
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
