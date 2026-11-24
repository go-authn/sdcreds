//go:build linux

package s6

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"
)

// A launch that fails is the error of startWith, promptly: no wait function is
// returned (calling it would block for ever), the forwarder never runs (there
// is no process to signal, so a signal stays where it is), and stop is called
// once.
func TestStartWithFailedLaunchReturnsItsError(t *testing.T) {
	old := restrict
	defer func() { restrict = old }()
	boom := errors.New("boom")
	restrict = func([]Cap) error { return boom }
	sigs := make(chan os.Signal, 1)
	sigs <- syscall.SIGHUP
	stopped := make(chan struct{})
	stops := 0
	type result struct {
		wait func() (int, error)
		err  error
	}
	res := make(chan result, 1)
	go func() {
		w, err := startWith(sigs, func() { stops++; close(stopped) }, User{UID: 12345, GID: 12345}, []string{"/bin/true"}, nil)
		res <- result{w, err}
	}()
	select {
	case r := <-res:
		if r.err == nil || r.wait != nil {
			t.Fatalf("a failed launch was reported as started: wait=%v err=%v", r.wait != nil, r.err)
		}
		if os.Geteuid() == 0 && !errors.Is(r.err, boom) {
			t.Errorf("not the error of the launch: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startWith did not return after a failed launch")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop was not called")
	}
	time.Sleep(50 * time.Millisecond)
	if stops != 1 {
		t.Errorf("stop called %d times", stops)
	}
	if len(sigs) != 1 {
		t.Error("the forwarder ran without a process")
	}
}
