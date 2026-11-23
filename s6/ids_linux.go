//go:build linux && !386 && !arm

package s6

import "syscall"

// The calls that set the ids of one thread, with ids of 32 bits.
const (
	trapSetresuid = syscall.SYS_SETRESUID
	trapSetresgid = syscall.SYS_SETRESGID
	trapSetgroups = syscall.SYS_SETGROUPS
)
