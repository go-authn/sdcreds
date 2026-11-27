package main

import (
	"os"
	"sync"
)

// stubGuard keeps a forwarded signal from reaching a process that is not the
// stub any more. On OpenBSD the standard library cannot tell, before it reaps a
// child, that the child is done (there is no waitid there): between the reap and
// its own bookkeeping the pid can be given to an unrelated process, and a signal
// sent by pid would land on it, from root. So the exit is observed WITHOUT
// reaping (a kqueue NOTE_EXIT: the zombie keeps the pid), the guard is marked
// gone under the lock the forwarder takes, and only then is the child reaped.
type stubGuard struct {
	mu   sync.Mutex
	gone bool
}

// markGone records that the stub has exited; it returns once any signal in
// flight has been sent, and no signal is sent after it.
func (g *stubGuard) markGone() {
	g.mu.Lock()
	g.gone = true
	g.mu.Unlock()
}

// signal sends s through send unless the stub is gone, and reports whether it did.
func (g *stubGuard) signal(send func(os.Signal) error, s os.Signal) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.gone {
		return false
	}
	_ = send(s)
	return true
}

// reapAfterExit waits for the exit to be observed, marks the guard, and only then
// reaps: this order is the whole fix.
func reapAfterExit(exited <-chan struct{}, g *stubGuard, reap func() error) error {
	<-exited
	g.markGone()
	return reap()
}
