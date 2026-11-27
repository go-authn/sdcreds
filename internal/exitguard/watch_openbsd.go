package exitguard

import "golang.org/x/sys/unix"

// WatchExit closes the returned channel when the process pid exits, WITHOUT
// reaping it: a kqueue NOTE_EXIT is delivered while the process is still a
// zombie, which holds its pid. pid must be a child of this process that nobody
// has waited for yet. A process that is already gone (ESRCH) counts as exited.
func WatchExit(pid int) (<-chan struct{}, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	// SetKevent sizes Ident for the architecture, so this package never makes a
	// 32-bit build fail for a reason other than the refusal in delivery.
	var ev unix.Kevent_t
	unix.SetKevent(&ev, pid, unix.EVFILT_PROC, unix.EV_ADD|unix.EV_ONESHOT)
	ev.Fflags = unix.NOTE_EXIT
	exited := make(chan struct{})
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		unix.Close(kq)
		if err == unix.ESRCH {
			close(exited)
			return exited, nil
		}
		return nil, err
	}
	go func() {
		defer unix.Close(kq)
		out := make([]unix.Kevent_t, 1)
		for {
			n, err := unix.Kevent(kq, nil, out, nil)
			if err == unix.EINTR {
				continue
			}
			if n > 0 || err != nil {
				close(exited)
				return
			}
		}
	}()
	return exited, nil
}
