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

// Seams for the tests: a signal can then be delivered at an exact point of Run.
var (
	notifySignals = signal.Notify
	stopSignals   = signal.Stop
)

// heldBuffer is how many signals wait for caught between two calls of it; a
// signal that finds the buffer full is dropped, never delivered.
const heldBuffer = 64

// holdSignals keeps the signals of forwarded from ending this process (their
// default action) until the returned function is called, and drops them: what
// is left to do is taking the credentials away, which must be finished however
// many times s6 asks to stop. caught reports (and forgets) the number of the
// first signal that would have ended the process since the last call, 0 when
// there is none: before the service runs, Run stops on it, after the clean-up.
//
// held is the channel the signals arrive on. Once the service runs, its
// forwarder is the only reader of held, so a signal is delivered to the service
// exactly once: one that came before the fork waits in the buffer and is read
// first, one that comes later is read when it arrives.
func holdSignals() (release func(), caught func() int, held <-chan os.Signal) {
	ch := make(chan os.Signal, heldBuffer)
	notifySignals(ch, forwarded...)
	release = func() { stopSignals(ch) }
	caught = func() int {
		first := 0
		for {
			select {
			case s := <-ch:
				// SIGCONT is ignored by default: it never ended this process.
				if n, ok := s.(syscall.Signal); ok && n != syscall.SIGCONT && first == 0 {
					first = int(n)
				}
			default:
				return first
			}
		}
	}
	return release, caught, ch
}
