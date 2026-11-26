//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds"
)

// ErrUntrustedSource is a source directory or file that someone else could have
// changed: a swapped sealed file is a rollback, or, with the null key, a secret
// of the attacker's choosing.
var ErrUntrustedSource = errors.New("delivery: untrusted credential source")

// ReadSource reads the sealed credentials of a source directory, one regular
// file each, in name order. It decrypts nothing.
//
// The directory is walked like the base directory: every component from "/" is
// opened without following a link, owned by root and not writable by group or
// others; each file is then opened relative to that judged descriptor, without
// following a link or waiting on a pipe, and must be a regular file of root that
// group and others cannot write. At most MaxEntries entries are read from the
// descriptor, and the sealed forms together are bounded while they are read.
func ReadSource(dir string) ([]Credential, error) {
	return ReadSourceTrusted(dir, trustedUID, ancestorsFrom)
}

// ReadSourceTrusted is ReadSource with the owner every directory and file must
// have, and the directory from which the ancestors are judged ("/" and root in
// production); a caller that tests as an ordinary user passes its own.
func ReadSourceTrusted(dir string, owner uint32, from string) ([]Credential, error) {
	// A link in the path is resolved first, and the directories it leads to are
	// judged like any other: a link someone else made can only lead where the
	// rules hold, and the walk itself follows nothing.
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	if rf, err := filepath.EvalSymlinks(from); err == nil {
		from = rf
	}
	fd, err := walkDir(real, owner, from, false)
	if err != nil {
		if errors.Is(err, ErrUntrustedPath) {
			return nil, fmt.Errorf("%w: %w", ErrUntrustedSource, err)
		}
		return nil, err
	}
	d := os.NewFile(uintptr(fd), dir)
	defer d.Close()
	ents, err := readDir(d, MaxEntries+1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(ents) > MaxEntries {
		return nil, fmt.Errorf("%w: %s holds more than %d entries", ErrTooManyEntry, dir, MaxEntries)
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	slices.Sort(names)
	out := make([]Credential, 0, len(names))
	total := 0
	for _, name := range names {
		if !sdcreds.NameValid(name) {
			return nil, fmt.Errorf("%w: credential %q", ErrBadName, name)
		}
		b, err := readSourceFile(fd, dir, name, owner)
		if err != nil {
			return nil, err
		}
		total += len(b)
		if total > maxSealedTotal {
			return nil, fmt.Errorf("%w: the credentials of %s exceed the limit", sdcreds.ErrTooLarge, dir)
		}
		out = append(out, Credential{Name: name, Sealed: b})
	}
	return out, nil
}

// Seams for the tests: an open descriptor that cannot be made to fail to stat
// or to read on a real system.
var (
	readDir  = func(d *os.File, n int) ([]os.DirEntry, error) { return d.ReadDir(n) }
	statFile = func(f *os.File) (os.FileInfo, error) { return f.Stat() }
	readFile = func(f *os.File) ([]byte, error) { return io.ReadAll(io.LimitReader(f, maxArmoured+1)) }
)

func readSourceFile(dfd int, dir, name string, owner uint32) ([]byte, error) {
	path := strings.TrimSuffix(dir, "/") + "/" + name
	fd, err := unix.Openat(dfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
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
	if sys, ok := st.Sys().(*syscall.Stat_t); !ok || sys.Uid != owner || st.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%w: %s must belong to uid %d and not be writable by group or others", ErrUntrustedSource, path, owner)
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
