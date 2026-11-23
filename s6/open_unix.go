//go:build unix

package s6

import (
	"os"
	"syscall"
)

// fchmodDir sets the mode of a directory through a descriptor opened without
// following a symbolic link: the umask plays no part in fchmod.
// A variable for the tests.
var fchmodDir = func(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Chmod(mode)
}

// openSource opens a credential file for reading without following a symbolic
// link and without blocking on a pipe; replaced by the tests.
var openSource = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
}
