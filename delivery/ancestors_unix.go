//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// trustedUID is the owner every ancestor of the base directory must have; a
// variable for the tests, which do not run as root.
var trustedUID = uint32(0)

// ancestorsFrom is the directory from which the ancestors are judged, "/" in
// production; a variable for the tests.
var ancestorsFrom = "/"

// Seams for the tests: system calls that cannot be made to fail on a real
// system.
var (
	openat  = unix.Openat
	fstat   = unix.Fstat
	mkdirat = unix.Mkdirat
	fchmod  = unix.Fchmod
	fchown  = unix.Fchown
)

// EnsureBase makes sure base exists and can be trusted, and returns nothing
// else: every directory from "/" down to base, base included, is opened one
// component at a time without following a symbolic link, is owned by root, and
// is not writable by group or others. A missing directory is created with mode
// 0711 (fchmod, so the umask plays no part). A link anywhere on the path is
// refused: mount(2) follows links and OpenBSD can neither forbid it nor mount by
// descriptor, so whoever could swap a path component could redirect the mount.
func EnsureBase(base string) error {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return fmt.Errorf("%w: %q", ErrBadBase, base)
	}
	fd, err := walkDir(base, trustedUID, ancestorsFrom, true)
	if err != nil {
		return err
	}
	unix.Close(fd)
	return nil
}

// walkDir opens dir one component at a time from "/", without following a
// symbolic link, and judges every directory from `from` down: owned by owner,
// not writable by group or others. With create, a missing directory is made
// (mode 0711, owned by owner). It returns a descriptor of dir, which is the
// directory that was judged: whatever is read through it cannot have been
// swapped for another by a change of a path component.
func walkDir(dir string, owner uint32, from string, create bool) (int, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := openat(unix.AT_FDCWD, "/", flags, 0)
	if err != nil {
		return -1, err
	}
	cur := "/"
	comps := strings.Split(strings.Trim(dir, "/"), "/")
	for _, comp := range append([]string{""}, comps...) {
		if comp != "" {
			next, err := openat(fd, comp, flags, 0)
			created := false
			if create && errors.Is(err, unix.ENOENT) {
				if err = mkdirat(fd, comp, 0o711); err == nil {
					created = true
					next, err = openat(fd, comp, flags, 0)
				}
			}
			unix.Close(fd)
			if err != nil {
				return -1, &os.PathError{Op: "open", Path: filepath.Join(cur, comp), Err: err}
			}
			fd, cur = next, filepath.Join(cur, comp)
			if created {
				if err := fchmod(fd, 0o711); err != nil {
					unix.Close(fd)
					return -1, err
				}
				if err := fchown(fd, int(owner), -1); err != nil {
					unix.Close(fd)
					return -1, err
				}
			}
		}
		if cur == from || strings.HasPrefix(cur, strings.TrimSuffix(from, "/")+"/") {
			var st unix.Stat_t
			if err := fstat(fd, &st); err != nil {
				unix.Close(fd)
				return -1, err
			}
			if err := judgeDir(cur, &st, owner); err != nil {
				unix.Close(fd)
				return -1, err
			}
		}
	}
	return fd, nil
}

func judgeDir(path string, st *unix.Stat_t, owner uint32) error {
	switch {
	case st.Uid != owner:
		return fmt.Errorf("%w: directory %s is owned by uid %d, not %d", ErrUntrustedPath, path, st.Uid, owner)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: directory %s is writable by group or others (%v)", ErrUntrustedPath, path, os.FileMode(st.Mode&0o777))
	}
	return nil
}
