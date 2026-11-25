//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds"
)

// ReadSource reads the sealed credentials of a source directory, one regular
// file each, in name order. It decrypts nothing. Every file is opened once,
// without following a link or waiting on a pipe, judged by its descriptor, and
// read up to a bound; an entry count above MaxEntries is refused before any
// file is opened. The directory itself is not walked for trust (parity with
// the s6 path): its contents are sealed, and a swap can only make a decryption
// fail.
func ReadSource(dir string) ([]Credential, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	if len(ents) > MaxEntries {
		return nil, fmt.Errorf("%w: %s holds %d entries, at most %d", ErrTooManyEntry, dir, len(ents), MaxEntries)
	}
	out := make([]Credential, 0, len(ents))
	for _, e := range ents {
		name := e.Name()
		if !sdcreds.NameValid(name) {
			return nil, fmt.Errorf("%w: credential %q", ErrBadName, name)
		}
		b, err := readSourceFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, Credential{Name: name, Sealed: b})
	}
	return out, nil
}

// Seams for the tests: an open descriptor that cannot be made to fail to stat
// or to read on a real system.
var (
	statFile = func(f *os.File) (os.FileInfo, error) { return f.Stat() }
	readFile = func(f *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(f, maxArmoured+1)) }
)

func readSourceFile(path string) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, fmt.Errorf("delivery: %s is not a regular file (a symbolic link is not followed)", path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := statFile(f)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("delivery: %s is not a regular file", path)
	}
	b, err := readFile(f)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	if len(b) > maxArmoured {
		return nil, fmt.Errorf("%w: %s is longer than %d bytes", sdcreds.ErrTooLarge, path, maxArmoured)
	}
	return b, nil
}
