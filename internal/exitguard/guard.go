// Package exitguard keeps a signal that root sends to its own child from
// reaching a process that is not the child any more.
//
// On OpenBSD the standard library cannot tell, before it reaps a child, that the
// child is done (there is no waitid there, os/wait_unimp.go): between the reap
// (os/exec_unix.go pidWait, Wait4) and its own bookkeeping (doRelease(statusDone))
// the pid can be given to an unrelated process, and a Process.Kill or
// Process.Signal in that window lands on it. The package therefore observes the
// exit WITHOUT reaping (a kqueue NOTE_EXIT: the zombie keeps the pid), marks a
// Guard under the lock every sender takes, and only then reaps.
package exitguard

import (
	"os"
	"os/exec"
	"sync"
	"time"
)

// Guard keeps a signal from being sent once the child has exited.
type Guard struct {
	mu   sync.Mutex
	gone bool
}

// MarkGone records that the child has exited; it returns once any signal in
// flight has been sent, and no signal is sent after it.
func (g *Guard) MarkGone() {
	g.mu.Lock()
	g.gone = true
	g.mu.Unlock()
}

// Signal sends s through send unless the child is gone, and reports whether it did.
func (g *Guard) Signal(send func(os.Signal) error, s os.Signal) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gone {
		return false
	}
	_ = send(s)
	return true
}

// ReapAfterExit waits for the exit to be observed, marks the guard, and only then
// reaps: this order is the whole fix.
func ReapAfterExit(exited <-chan struct{}, g *Guard, reap func() error) error {
	<-exited
	g.MarkGone()
	return reap()
}

// Run starts c, waits for it, and kills it if it has not ended after timeout,
// like exec.CommandContext with a deadline, except that the kill is never sent
// once the child has exited: exec.CommandContext's kill can follow the reap on
// OpenBSD (os/exec/exec.go watchCtx runs Cancel while Wait has returned from
// Process.Wait but has not yet received from ctxResult).
func Run(c *exec.Cmd, timeout time.Duration) error {
	return run(c, timeout, WatchExit, func(p *os.Process) error { return p.Kill() }, (*exec.Cmd).Wait)
}

// run is Run with the observation of the exit, the kill and the reap given.
func run(c *exec.Cmd, timeout time.Duration, watch func(pid int) (<-chan struct{}, error), kill func(*os.Process) error, reap func(*exec.Cmd) error) error {
	if err := c.Start(); err != nil {
		return err
	}
	exited, err := watch(c.Process.Pid)
	if err != nil {
		// Nobody reaps before the Wait below, so the pid is still the child's.
		_ = kill(c.Process)
		_ = reap(c)
		return err
	}
	var g Guard
	done := make(chan error, 1)
	go func() { done <- ReapAfterExit(exited, &g, func() error { return reap(c) }) }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err
	case <-timer.C:
		g.Signal(func(os.Signal) error { return kill(c.Process) }, nil)
		return <-done
	}
}
