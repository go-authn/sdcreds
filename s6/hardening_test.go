//go:build unix

package s6

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// Mounts stack: Run clears whatever an earlier run left on the directory and
// Finish peels every layer before it removes the directory.
func TestStackedMountsAreAllRemoved(t *testing.T) {
	r, c := newRig(t), config(t)
	r.layers = 2
	ops := r.ops()
	var seen = -1
	mount := ops.MountRAM
	ops.MountRAM = func(d string) error {
		seen = r.layers
		return mount(d)
	}
	if err := Run(c, ops); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	if seen != 0 {
		t.Errorf("%d mounts were still stacked when the new one was made", seen)
	}
	if r.layers != 0 {
		t.Errorf("%d layers left after a failed exec", r.layers)
	}

	base := t.TempDir()
	os.Mkdir(Dir(base, "web"), 0o700)
	r = newRig(t)
	r.layers = 3
	if err := Finish("web", base, r.ops()); err != nil {
		t.Fatal(err)
	}
	if r.layers != 0 {
		t.Errorf("Finish left %d layers", r.layers)
	}
	if _, err := os.Stat(Dir(base, "web")); err == nil {
		t.Error("directory kept")
	}
}

// A mount that cannot be peeled is an error after a bounded number of tries,
// not an endless loop.
func TestUnmountLoopIsBounded(t *testing.T) {
	base := t.TempDir()
	os.Mkdir(Dir(base, "web"), 0o700)
	n := 0
	ops := newRig(t).ops()
	ops.Unmount = func(string) error { n++; return nil }
	err := Finish("web", base, ops)
	if err == nil || !strings.Contains(err.Error(), "still mounted") {
		t.Fatalf("%v", err)
	}
	if n != maxLayers {
		t.Errorf("%d unmount calls, want %d", n, maxLayers)
	}
}

// A command that cannot be found fails before anything is mounted, and a
// cleanup that fails after the exec is said out loud.
func TestCommandIsResolvedBeforeMounting(t *testing.T) {
	r, c := newRig(t), config(t)
	ops := r.ops()
	boom := errors.New("not found")
	ops.Resolve = func(string) (string, error) { return "", boom }
	err := Run(c, ops)
	if !errors.Is(err, boom) {
		t.Fatalf("%v", err)
	}
	for _, step := range []string{"mount", "unshare", "drop", "exec"} {
		if slices.Contains(r.calls, step) {
			t.Errorf("%s reached: %v", step, r.calls)
		}
	}

	r, c = newRig(t), config(t)
	ops = r.ops()
	var resolved string
	ops.Resolve = func(s string) (string, error) { resolved = s; return s, nil }
	stuck := errors.New("operation not permitted")
	ops.Exec = func([]string, []string) error {
		r.fail["unmount"] = stuck // the privileges are gone: nothing can unmount
		return errExec
	}
	err = Run(c, ops)
	if resolved != "/bin/web" {
		t.Errorf("resolved %q", resolved)
	}
	if !errors.Is(err, errExec) || !errors.Is(err, stuck) || !strings.Contains(err.Error(), "credentials left mounted at "+Dir(c.BaseDir, "web")) {
		t.Errorf("%v", err)
	}
}

// The base directory is traversable by everyone; the directory of the service
// is private.
func TestDirectoryModes(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	r, c := newRig(t), config(t)
	c.BaseDir = filepath.Join(c.BaseDir, "run", "sdcreds")
	if err := Run(c, r.ops()); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	if r.dirMode != 0o700 {
		t.Errorf("service directory mode %v", r.dirMode)
	}
	st, err := os.Stat(c.BaseDir)
	if err != nil || st.Mode().Perm() != 0o755 {
		t.Errorf("base directory: %v %v", st, err)
	}
}
