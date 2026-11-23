//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/go-authn/sdcreds"
)

// trustedUID is the owner a key file named on the command line of the
// privileged path must have; a variable for the tests, which do not run as root.
var trustedUID = uint32(0)

// Seams for the tests: neither call can fail on a regular file that was just
// opened.
var (
	statTrusted   = func(f *os.File) (os.FileInfo, error) { return f.Stat() }
	readMachineID = func(f *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(f, 64)) }
)

// openTrusted opens a key file without following a final symbolic link and
// judges the descriptor: absolute and normalised path, a regular file, owned by
// trustedUID, not writable by group or others.
func openTrusted(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("%w: %q must be an absolute, normalised path", sdcreds.ErrInvalid, path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	st, err := statTrusted(f)
	if err == nil {
		err = judgeTrusted(path, st)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func judgeTrusted(path string, st os.FileInfo) error {
	sys, ok := st.Sys().(*syscall.Stat_t)
	switch {
	case !st.Mode().IsRegular():
		return fmt.Errorf("%s is not a regular file", path)
	case !ok || sys.Uid != trustedUID:
		return fmt.Errorf("%s is not owned by uid %d", path, trustedUID)
	case st.Mode().Perm()&0o022 != 0:
		return fmt.Errorf("%s is writable by group or others (%v)", path, st.Mode().Perm())
	}
	return nil
}

func checkTrusted(path string) error {
	f, err := openTrusted(path)
	if err != nil {
		return err
	}
	return f.Close()
}

// readTrustedMachineID reads a machine id from a file that openTrusted accepts.
func readTrustedMachineID(path string) ([16]byte, error) {
	f, err := openTrusted(path)
	if err != nil {
		return [16]byte{}, fmt.Errorf("--machine-id-file: %w", err)
	}
	defer f.Close()
	b, err := readMachineID(f)
	if err != nil {
		return [16]byte{}, err
	}
	return sdcreds.ParseMachineID(b)
}
