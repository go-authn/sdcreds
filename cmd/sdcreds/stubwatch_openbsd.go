package main

import "golang.org/x/sys/unix"

// watchExit closes the returned channel when the process pid exits, WITHOUT
// reaping it: a kqueue NOTE_EXIT is delivered while the process is still a
// zombie, which holds its pid. pid must be a child of this process that nobody
// has waited for yet. A process that is already gone (ESRCH) counts as exited.
func watchExit(pid int) (<-chan struct{}, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	ev := unix.Kevent_t{Ident: uint64(pid), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
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
