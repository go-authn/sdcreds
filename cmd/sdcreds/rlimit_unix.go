//go:build unix

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// rlimitIDs maps the resources of a login class to the system's.
var rlimitIDs = map[string]int{
	"cpu": syscall.RLIMIT_CPU, "fsize": syscall.RLIMIT_FSIZE, "data": syscall.RLIMIT_DATA,
	"stack": syscall.RLIMIT_STACK, "core": syscall.RLIMIT_CORE, "rss": unix.RLIMIT_RSS,
	"memlock": unix.RLIMIT_MEMLOCK, "nproc": unix.RLIMIT_NPROC, "nofile": syscall.RLIMIT_NOFILE,
}

// Seams for the tests.
var (
	getrlimit = syscall.Getrlimit
	setrlimit = syscall.Setrlimit
)

// applyLimits sets the limits of a class on this process. The process is not
// root, so it can only lower: a value above the current hard limit is clamped
// to it, and a limit the system refuses is an error, never skipped. The soft
// limit is never left above the hard one.
func applyLimits(ls []classRlimit) error {
	for _, l := range ls {
		id, ok := rlimitIDs[l.Resource]
		if !ok {
			return fmt.Errorf("%w: unknown resource %q", errClassLimit, l.Resource)
		}
		var cur syscall.Rlimit
		if err := getrlimit(id, &cur); err != nil {
			return fmt.Errorf("getrlimit %s: %w", l.Resource, err)
		}
		next := cur
		if l.Max.Set {
			next.Max = min(cur.Max, wanted(l.Max))
		}
		if l.Cur.Set {
			next.Cur = wanted(l.Cur)
		}
		next.Cur = min(next.Cur, next.Max)
		if err := setrlimit(id, &next); err != nil {
			return fmt.Errorf("setrlimit %s: %w", l.Resource, err)
		}
	}
	return nil
}

// wanted is the value as a number; infinity is the largest, then clamped by
// the hard limit.
func wanted(v limitValue) uint64 {
	if v.Inf {
		return ^uint64(0)
	}
	return v.N
}
