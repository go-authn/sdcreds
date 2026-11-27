package main

import (
	"fmt"
	"io"
)

// exitReleaseFailed is the status of a run whose release did not end well:
// processes of the target may be left, or the mount.
const exitReleaseFailed = 70

// releaseExit reports a failed release on w and makes the status 70, whatever the
// program's own status was: a survivor must be visible to the supervisor, and the
// program's status, which would hide it, is printed instead.
func releaseExit(w io.Writer, err error, code int) int {
	if err == nil {
		return code
	}
	fmt.Fprintf(w, "sdcreds run: release: %v\n", err)
	if code != 0 {
		fmt.Fprintf(w, "sdcreds run: the program's own status was %d\n", code)
	}
	return exitReleaseFailed
}
