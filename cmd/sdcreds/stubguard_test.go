package main

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
)

// The fix is an ORDER: the exit is observed, the guard is marked gone, and only
// then is the child reaped. A signal forwarded while the reap runs (the window
// in which the pid may already be somebody else's) must send nothing.
func TestNoSignalIsSentOnceTheExitIsObserved(t *testing.T) {
	var g stubGuard
	var sent atomic.Int32
	send := func(os.Signal) error { sent.Add(1); return nil }

	exited := make(chan struct{})
	close(exited)
	reaped := false
	err := reapAfterExit(exited, &g, func() error {
		// The reap is under way: a forwarder racing it must find the guard shut.
		if g.signal(send, syscall.SIGTERM) {
			t.Error("a signal was sent while the stub was being reaped")
		}
		reaped = true
		return nil
	})
	if err != nil || !reaped {
		t.Fatalf("reap not run or failed: %v", err)
	}
	if n := sent.Load(); n != 0 {
		t.Fatalf("%d signal(s) sent after the exit was observed", n)
	}
}

func TestSignalIsForwardedWhileTheStubRuns(t *testing.T) {
	var g stubGuard
	var got os.Signal
	if !g.signal(func(s os.Signal) error { got = s; return nil }, syscall.SIGTERM) {
		t.Fatal("a running stub got no signal")
	}
	if got != syscall.SIGTERM {
		t.Fatalf("forwarded %v, want SIGTERM", got)
	}
}

func TestReapWaitsForTheObservedExit(t *testing.T) {
	var g stubGuard
	exited := make(chan struct{})
	reaped := make(chan struct{})
	go func() {
		_ = reapAfterExit(exited, &g, func() error { close(reaped); return nil })
	}()
	select {
	case <-reaped:
		t.Fatal("reaped before the exit was observed")
	default:
	}
	close(exited)
	<-reaped
	if g.signal(func(os.Signal) error { return nil }, syscall.SIGTERM) {
		t.Fatal("the guard is still open after the reap")
	}
}
