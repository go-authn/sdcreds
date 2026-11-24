//go:build unix

package main

import (
	"os"
	"syscall"
)

// openExclusive creates name, which must not exist, without following a symlink.
func openExclusive(name string) (*os.File, error) {
	fd, err := syscall.Open(name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(fd), name), nil
}
