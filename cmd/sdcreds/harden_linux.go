//go:build linux

package main

import "syscall"

const prSetDumpable = 4 // PR_SET_DUMPABLE, linux/prctl.h

// hardenOS makes the process non-dumpable (no core file, no ptrace by the same
// user, /proc/PID/mem closed to it) and sets the core file size limit to zero.
func hardenOS() {
	syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
}
