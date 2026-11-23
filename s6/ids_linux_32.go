//go:build linux && (386 || arm)

package s6

import "syscall"

// On these architectures the plain calls take 16-bit ids; the 32-bit ones are
// the ones that must set an id above 65535.
const (
	trapSetresuid = syscall.SYS_SETRESUID32
	trapSetresgid = syscall.SYS_SETRESGID32
	trapSetgroups = syscall.SYS_SETGROUPS32
)
