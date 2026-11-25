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
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := openat(unix.AT_FDCWD, "/", flags, 0)
	if err != nil {
		return err
	}
	cur := "/"
	comps := strings.Split(strings.Trim(base, "/"), "/")
	for _, comp := range append([]string{""}, comps...) {
		if comp != "" {
			next, err := openat(fd, comp, flags, 0)
			created := false
			if errors.Is(err, unix.ENOENT) {
				if err = mkdirat(fd, comp, 0o711); err == nil {
					created = true
					next, err = openat(fd, comp, flags, 0)
				}
			}
			unix.Close(fd)
			if err != nil {
				return &os.PathError{Op: "open", Path: filepath.Join(cur, comp), Err: err}
			}
			fd, cur = next, filepath.Join(cur, comp)
			if created {
				if err := fchmod(fd, 0o711); err != nil {
					unix.Close(fd)
					return err
				}
				if err := fchown(fd, int(trustedUID), -1); err != nil {
					unix.Close(fd)
					return err
				}
			}
		}
		if cur == ancestorsFrom || strings.HasPrefix(cur, strings.TrimSuffix(ancestorsFrom, "/")+"/") {
			var st unix.Stat_t
			if err := fstat(fd, &st); err != nil {
				unix.Close(fd)
				return err
			}
			if err := judgeDir(cur, &st); err != nil {
				unix.Close(fd)
				return err
			}
		}
	}
	unix.Close(fd)
	return nil
}

func judgeDir(path string, st *unix.Stat_t) error {
	switch {
	case st.Uid != trustedUID:
		return fmt.Errorf("%w: directory %s is owned by uid %d, not %d", ErrUntrustedPath, path, st.Uid, trustedUID)
	case st.Mode&0o022 != 0:
		return fmt.Errorf("%w: directory %s is writable by group or others (%v)", ErrUntrustedPath, path, os.FileMode(st.Mode&0o777))
	}
	return nil
}
