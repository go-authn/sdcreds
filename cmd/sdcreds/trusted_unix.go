//go:build unix

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

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
	// A link above the file is resolved, and the directories it leads to are
	// judged like any other: a link that someone else made can only lead where
	// the rules above hold. The walk itself follows nothing.
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	dirfd, err := walkTrustedDirs(dir)
	if err != nil {
		return nil, err
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat(dirfd, filepath.Base(path), unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
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

// ancestorsFrom is the directory from which the ancestors of a key file are
// judged, "/" in production; a variable for the tests, which do not run as root.
var ancestorsFrom = "/"

// Seams for the tests: a system call that cannot be made to fail on a real
// system.
var (
	openat = unix.Openat
	fstat  = unix.Fstat
)

// walkTrustedDirs opens the directory that holds path one component at a time,
// from "/", without following a symbolic link, and judges every directory it
// crosses: the owner is trustedUID and neither group nor others can write. A
// directory that anyone else can write to would let them swap the file, and a
// link in the path lets whoever owns the link point it elsewhere. It returns a
// descriptor of dir.
func walkTrustedDirs(dir string) (int, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := openat(unix.AT_FDCWD, "/", flags, 0)
	if err != nil {
		return -1, err
	}
	cur := "/"
	for _, comp := range append([]string{""}, strings.Split(strings.Trim(dir, "/"), "/")...) {
		if comp != "" {
			next, err := openat(fd, comp, flags, 0)
			unix.Close(fd)
			if err != nil {
				return -1, &os.PathError{Op: "open", Path: filepath.Join(cur, comp), Err: err}
			}
			fd, cur = next, filepath.Join(cur, comp)
		}
		if cur == ancestorsFrom || strings.HasPrefix(cur, strings.TrimSuffix(ancestorsFrom, "/")+"/") {
			var st unix.Stat_t
			if err := fstat(fd, &st); err != nil {
				unix.Close(fd)
				return -1, err
			}
			if err := judgeDir(cur, &st); err != nil {
				unix.Close(fd)
				return -1, err
			}
		}
	}
	return fd, nil
}

func judgeDir(path string, st *unix.Stat_t) error {
	switch {
	case st.Uid != trustedUID:
		return fmt.Errorf("directory %s of the path is not owned by uid %d", path, trustedUID)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("directory %s of the path is writable by group or others (%v)", path, os.FileMode(st.Mode&0o777))
	}
	return nil
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
