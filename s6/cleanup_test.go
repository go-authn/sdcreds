package s6

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var errBoom = errors.New("boom")

// reopenStages lets TempDir's cleanup delete a staging directory the run left
// read-only, as the failure being tested does.
func reopenStages(t *testing.T, base string) {
	t.Cleanup(func() {
		stages, _ := filepath.Glob(filepath.Join(base, ".stage-*", "mnt"))
		for _, s := range stages {
			_ = os.Chmod(s, 0o700)
		}
	})
}

// A credential directory that cannot be unmounted after a run that succeeded is
// reported alone: the run had no error to join it to.
func TestRunReportsAMountLeftAfterASuccessfulRun(t *testing.T) {
	r, c := newRig(t), config(t)
	ops := r.ops()
	started := false
	ops.Start = func(User, []string, []string) (func() (int, error), error) {
		started = true
		return func() (int, error) { return 0, nil }, nil
	}
	unmount := ops.Unmount
	ops.Unmount = func(dir string) error {
		if started {
			return errBoom
		}
		return unmount(dir)
	}
	err := Run(c, ops)
	want := "credentials left mounted at " + Dir(c.BaseDir, c.Service) + ": boom"
	if err == nil || err.Error() != want {
		t.Fatalf("got %v, want %q", err, want)
	}
	if !errors.Is(err, errBoom) {
		t.Fatalf("the cause is lost: %v", err)
	}
}

// A staging mount that cannot be unmounted is reported next to the error that
// ended the run, and neither hides the other.
func TestRunReportsAStagingMountLeftBehindAFailure(t *testing.T) {
	errRemount := errors.New("remount failed")
	r, c := newRig(t), config(t)
	r.fail["remount"] = errRemount
	reopenStages(t, c.BaseDir)
	ops := r.ops()
	unmount := ops.Unmount
	ops.Unmount = func(dir string) error {
		if filepath.Base(dir) == "mnt" {
			return errBoom
		}
		return unmount(dir)
	}
	err := Run(c, ops)
	if !errors.Is(err, errRemount) || !errors.Is(err, errBoom) {
		t.Fatalf("both causes must survive: %v", err)
	}
	if !strings.Contains(err.Error(), "credentials left mounted at") {
		t.Fatalf("the left mount is not named: %v", err)
	}
}

// When the unmount works but the staging directory cannot be removed, the
// run says so instead of leaving it silently.
func TestRunReportsADirectoryItCouldNotRemove(t *testing.T) {
	errRemount := errors.New("remount failed")
	r, c := newRig(t), config(t)
	r.fail["remount"] = errRemount
	reopenStages(t, c.BaseDir)
	ops := r.ops()
	// An unmount that leaves the files behind: the staging directory is not empty.
	ops.Unmount = func(dir string) error {
		if r.layers[dir] == 0 {
			return ErrNotMounted
		}
		r.layers[dir]--
		return nil
	}
	err := Run(c, ops)
	if !errors.Is(err, errRemount) {
		t.Fatalf("the failure of the run is lost: %v", err)
	}
	if !strings.Contains(err.Error(), "could not remove") {
		t.Fatalf("the directory left behind is not reported: %v", err)
	}
}

// makeBase does not fail for a directory it could not create: checkBase
// judges what is there.
func TestMakeBaseLeavesAFailedCreationToCheckBase(t *testing.T) {
	file := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := makeBase(filepath.Join(file, "sub")); err != nil {
		t.Fatalf("makeBase: %v", err)
	}
}
