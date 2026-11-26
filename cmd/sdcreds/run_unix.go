//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"syscall"
)

// execAncestorsFrom is the highest directory canExecAs judges, "/" in
// production; a variable for the tests, whose temporary directories sit under
// a private parent.
var execAncestorsFrom = "/"

// statPath is os.Stat; a variable so that a test can make a stat fail between
// the resolution of a path and its judgement (a race in production).
var statPath = os.Stat

// canExecAs says, from stat alone, whether a process with these ids could
// execute path: a regular file with an execute bit that applies to the user,
// reached through directories the user can search. It follows symbolic links
// by resolving them first. It is a pre-check, not the access decision: the
// kernel decides at exec, and a stub that cannot exec fails closed.
func canExecAs(path string, uid, gid int, groups []int) error {
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	for d := filepath.Dir(real); ; d = filepath.Dir(d) {
		fi, err := statPath(d)
		if err != nil {
			return err
		}
		if !modeAllows(fi, 0o1, uid, gid, groups) {
			return fmt.Errorf("directory %s is not searchable by uid %d", d, uid)
		}
		if d == "/" || d == execAncestorsFrom || filepath.Dir(d) == d {
			break
		}
	}
	fi, err := statPath(real)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return errors.New(real + " is not a regular file")
	}
	if !modeAllows(fi, 0o1, uid, gid, groups) {
		return fmt.Errorf("%s is not executable by uid %d", real, uid)
	}
	return nil
}

// modeAllows applies the owner, group, other classes of POSIX access to bit
// (1 = execute): the first class that matches decides.
func modeAllows(fi os.FileInfo, bit uint32, uid, gid int, groups []int) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	perm := uint32(fi.Mode().Perm())
	switch {
	case int(st.Uid) == uid:
		return perm>>6&bit != 0
	case int(st.Gid) == gid || slices.Contains(groups, int(st.Gid)):
		return perm>>3&bit != 0
	default:
		return perm&bit != 0
	}
}
