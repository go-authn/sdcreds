package main

import (
	"fmt"
	"io"
)

// exitReleaseFailed is the status of a run whose program ended well but whose
// release did not: processes of the target may be left, or the mount.
const exitReleaseFailed = 70

// releaseExit reports a failed release on w and makes the status non-zero: the
// program's own status is kept when it is already a failure.
func releaseExit(w io.Writer, err error, code int) int {
	if err == nil {
		return code
	}
	fmt.Fprintf(w, "sdcreds run: release: %v\n", err)
	if code == 0 {
		return exitReleaseFailed
	}
	return code
}
