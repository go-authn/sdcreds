//go:build unix

package main

import (
	"errors"
	"syscall"
	"testing"
)

func TestApplyLimitsRefusesWhatItCannotRead(t *testing.T) {
	oldGet, oldSet := getrlimit, setrlimit
	t.Cleanup(func() { getrlimit, setrlimit = oldGet, oldSet })
	sets := 0
	setrlimit = func(int, *syscall.Rlimit) error { sets++; return nil }
	getrlimit = func(int, *syscall.Rlimit) error { return nil }
	one := limitValue{Set: true, N: 1}
	if err := applyLimits([]classRlimit{{Resource: "bogus", Cur: one}}); !errors.Is(err, errClassLimit) || sets != 0 {
		t.Errorf("unknown resource: %v (%d sets)", err, sets)
	}
	boom := errors.New("boom")
	getrlimit = func(int, *syscall.Rlimit) error { return boom }
	if err := applyLimits([]classRlimit{{Resource: "nofile", Cur: one}}); !errors.Is(err, boom) || sets != 0 {
		t.Errorf("getrlimit failure: %v (%d sets)", err, sets)
	}
}
