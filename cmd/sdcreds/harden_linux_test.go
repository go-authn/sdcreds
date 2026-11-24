//go:build linux

package main

import (
	"syscall"
	"testing"
)

func TestHardenOSDropsDumpableAndCoreLimit(t *testing.T) {
	hardenOS()
	dumpable, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, 3, 0, 0) // PR_GET_DUMPABLE
	if errno != 0 || dumpable != 0 {
		t.Errorf("dumpable=%d errno=%v", dumpable, errno)
	}
	var l syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_CORE, &l); err != nil || l.Cur != 0 || l.Max != 0 {
		t.Errorf("core limit %+v %v", l, err)
	}
}
