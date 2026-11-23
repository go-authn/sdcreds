//go:build unix

package s6

import (
	"os"
	"os/signal"
	"syscall"
)

// forwarded are the signals that s6 (and a terminal) send to a service; the
// process that s6 supervises is this one, and the service must see them.
var forwarded = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGALRM, syscall.SIGCONT,
}

// holdSignals keeps the signals of forwarded from ending this process (their
// default action) until the returned function is called, and drops them: the
// service is gone, and what is left is taking its credentials away, which must
// be finished however many times s6 asks to stop.
func holdSignals() (release func()) {
	ch := make(chan os.Signal, 16)
	signal.Notify(ch, forwarded...)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-ch:
			case <-done:
				return
			}
		}
	}()
	return func() {
		signal.Stop(ch)
		close(done)
	}
}
