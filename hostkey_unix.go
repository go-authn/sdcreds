//go:build unix

package sdcreds

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// Seams for the tests: failures of the kernel that a test cannot provoke.
var (
	// openSecret opens without following a final symlink (cu.c:577).
	openSecret = func(path string) (*os.File, error) {
		// O_NONBLOCK: opening a FIFO there must fail the type check below, not
		// wait for a writer forever; a regular file ignores it.
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NOCTTY|syscall.O_NONBLOCK, 0)
		if err != nil {
			return nil, &os.PathError{Op: "open", Path: path, Err: err}
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	readFull = io.ReadFull
	syncFile = func(f *os.File) error { return f.Sync() }
	geteuid  = os.Geteuid
)

// ownerTrusted says whether a host secret owned by uid may be used by a process
// running as euid: its owner is root or the user running it, nobody else.
func ownerTrusted(uid uint32, euid int) bool { return uid == 0 || int64(uid) == int64(euid) }

// readHostSecret returns the whole file (machine id prefix included).
func readHostSecret(path string) ([]byte, error) {
	f, err := openSecret(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	var links uint64 = 1
	trusted := true
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		links = uint64(st.Nlink)
		trusted = ownerTrusted(st.Uid, geteuid())
	}
	size := fi.Size()
	switch {
	case !fi.Mode().IsRegular():
		return nil, fmt.Errorf("sdcreds: %s is not a regular file", path)
	case !trusted:
		return nil, fmt.Errorf("sdcreds: %s is owned by neither root nor the current user, refusing", path)
	case links == 0:
		return nil, fmt.Errorf("sdcreds: %s was deleted", path)
	case links > 1:
		return nil, fmt.Errorf("sdcreds: %s has too many links, refusing", path)
	case fi.Mode() != 0o400: // permission bits and setuid/setgid/sticky alike
		return nil, fmt.Errorf("sdcreds: %s has permissive access mode, refusing (want 0400)", path)
	case size < 16+1:
		return nil, fmt.Errorf("sdcreds: %s is too small, refusing", path)
	case size > HostSecretMax:
		return nil, fmt.Errorf("sdcreds: %s is too big, refusing: %w", path, ErrTooLarge)
	}
	buf := make([]byte, size+1)
	n, err := readFull(f, buf)
	if err != nil && err != io.ErrUnexpectedEOF {
		clear(buf)
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if int64(n) != size { // the size changed under us (cu.c:629)
		clear(buf)
		return nil, fmt.Errorf("sdcreds: failed to read %s: size changed", path)
	}
	return buf[:n], nil
}

func createHostSecret(path string, machineID [16]byte) ([]byte, error) {
	dir := filepath.Dir(path)
	// A failure to create the directory surfaces as the error of the open below.
	_ = os.MkdirAll(dir, 0o755)
	tmp, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf(".sdcreds-%d.tmp", os.Getpid())), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	prefix := HostSecretMachineID(machineID)
	data := make([]byte, HostSecretDataSize)
	rand.Read(data) // never fails since Go 1.24
	_, werr := tmp.Write(append(append([]byte{}, prefix[:]...), data...))
	if err := errors.Join(werr, tmp.Chmod(0o400), syncFile(tmp)); err != nil {
		return nil, err
	}
	// link(2) refuses to replace an existing file, like link_tmpfile_at.
	if err := os.Link(tmp.Name(), path); err != nil {
		return nil, err
	}
	return data, nil
}
