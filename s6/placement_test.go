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

// The base directory decides where credentials are mounted and what is
// unmounted: it is root's, or the running user's, and no one else can write it.
func TestBaseDirectoryOwnerAndMode(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o700} {
		dir := t.TempDir()
		os.Chmod(dir, mode)
		st, _ := os.Stat(dir)
		if err := checkBaseInfo(dir, st, os.Geteuid()); err != nil {
			t.Errorf("%v refused: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777, 0o722} {
		dir := t.TempDir()
		os.Chmod(dir, mode)
		st, _ := os.Stat(dir)
		if err := checkBaseInfo(dir, st, os.Geteuid()); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Errorf("%v accepted: %v", mode, err)
		}
	}
	if os.Geteuid() != 0 {
		dir := t.TempDir()
		st, _ := os.Stat(dir)
		if err := checkBaseInfo(dir, st, os.Geteuid()+1); err == nil || !strings.Contains(err.Error(), "owned by") {
			t.Errorf("a foreign owner was accepted: %v", err)
		}
	}
	file := filepath.Join(t.TempDir(), "f")
	os.WriteFile(file, nil, 0o600)
	st, _ := os.Stat(file)
	if err := checkBaseInfo(file, st, os.Geteuid()); err == nil {
		t.Error("a file was accepted as base directory")
	}

	// and Run and Finish refuse before they mount or unmount anything
	r, c := newRig(t), config(t)
	os.Chmod(c.BaseDir, 0o777)
	if err := Run(c, r.ops()); err == nil || slices.Contains(r.calls, "mount") || slices.Contains(r.calls, "unmount") {
		t.Errorf("Run: %v %v", err, r.calls)
	}
	r = newRig(t)
	if err := Finish("web", c.BaseDir, r.ops()); err == nil || slices.Contains(r.calls, "unmount") {
		t.Errorf("Finish: %v %v", err, r.calls)
	}
}

// A symbolic link at the place of the credential directory is never followed.
func TestSymlinkAtDirectoryIsRefused(t *testing.T) {
	r, c := newRig(t), config(t)
	victim := t.TempDir()
	os.WriteFile(filepath.Join(victim, "keep"), []byte("x"), 0o600)
	if err := os.Symlink(victim, Dir(c.BaseDir, "web")); err != nil {
		t.Fatal(err)
	}
	err := Run(c, r.ops())
	if err == nil || errors.Is(err, errExec) || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("Run: %v", err)
	}
	for _, call := range []string{"mount", "unmount", "chown", "remount", "move"} {
		if slices.Contains(r.calls, call) {
			t.Errorf("%s reached: %v", call, r.calls)
		}
	}

	r = newRig(t)
	err = Finish("web", c.BaseDir, r.ops())
	if err == nil || slices.Contains(r.calls, "unmount") {
		t.Errorf("Finish: %v %v", err, r.calls)
	}
	if _, err := os.Stat(filepath.Join(victim, "keep")); err != nil {
		t.Errorf("the target of the link was touched: %v", err)
	}
	if st, err := os.Lstat(Dir(c.BaseDir, "web")); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the link was removed: %v", err)
	}
}

// Only a memory file system is detached: something else mounted at the
// directory was not put there by this package.
func TestOnlyMemoryFilesystemsAreUnmounted(t *testing.T) {
	for typ, want := range map[string]bool{"ext4": false, "overlay": false, "0x1234": false, "tmpfs": true, "ramfs": true} {
		base := t.TempDir()
		os.Mkdir(Dir(base, "web"), 0o700)
		r := newRig(t)
		r.layers[Dir(base, "web")] = 1
		ops := r.ops()
		ops.FSType = func(string) (string, error) {
			if r.layers[Dir(base, "web")] == 0 {
				return "ext4", nil // what lies below
			}
			return typ, nil
		}
		if err := Finish("web", base, ops); err != nil {
			t.Fatalf("%s: %v", typ, err)
		}
		if got := slices.Contains(r.calls, "unmount"); got != want {
			t.Errorf("%s: unmounted=%v want %v", typ, got, want)
		}
	}
	// a file system that cannot be identified is an error, not a guess
	base := t.TempDir()
	os.Mkdir(Dir(base, "web"), 0o700)
	r := newRig(t)
	ops := r.ops()
	boom := errors.New("statfs failed")
	ops.FSType = func(string) (string, error) { return "", boom }
	if err := Finish("web", base, ops); !errors.Is(err, boom) || slices.Contains(r.calls, "unmount") {
		t.Errorf("%v %v", err, r.calls)
	}
}

// The credentials are mounted and frozen out of the service user's reach: the
// staging mount is under a directory only the owner can enter, never at the
// final path, and is read-only (0500) when it is moved into place.
func TestStagingMountIsPrivateUntilPlaced(t *testing.T) {
	r, c := newRig(t), config(t)
	dir := Dir(c.BaseDir, "web")
	ops := r.ops()
	var mounted, parentMode, moved = "", os.FileMode(0), ""
	mount := ops.MountRAM
	ops.MountRAM = func(d string) error {
		mounted = d
		if st, err := os.Stat(filepath.Dir(d)); err == nil {
			parentMode = st.Mode().Perm()
		}
		return mount(d)
	}
	move := ops.Move
	ops.Move = func(src, dst string) error {
		moved = dst
		if src != mounted {
			t.Errorf("moved %s, mounted %s", src, mounted)
		}
		return move(src, dst)
	}
	if err := Run(c, ops); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	if mounted == "" || mounted == dir || filepath.Dir(filepath.Dir(mounted)) != c.BaseDir || !strings.HasPrefix(filepath.Base(filepath.Dir(mounted)), ".stage-") {
		t.Errorf("mounted at %q", mounted)
	}
	if parentMode != 0o700 {
		t.Errorf("the staging parent is %v", parentMode)
	}
	if moved != dir {
		t.Errorf("moved to %q", moved)
	}
	ents, _ := os.ReadDir(c.BaseDir)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".stage-") {
			t.Errorf("%s left behind", e.Name())
		}
	}
}

// The service is not handed the paths of the host's key material.
func TestServiceEnvironmentHoldsNoKeyPaths(t *testing.T) {
	r, c := newRig(t), config(t)
	c.Env = []string{"PATH=/bin", "SYSTEMD_CREDENTIAL_SECRET=/etc/credstore/s", "SDCREDS_MACHINE_ID_FILE=/x", "SYSTEMD_CREDENTIAL_SECRET_X=keep", "HOME=/h"}
	if err := Run(c, r.ops()); !errors.Is(err, errExec) {
		t.Fatal(err)
	}
	want := []string{"PATH=/bin", "SYSTEMD_CREDENTIAL_SECRET_X=keep", "HOME=/h", EnvVar + "=" + Dir(c.BaseDir, "web")}
	if !slices.Equal(r.env, want) {
		t.Errorf("env %v", r.env)
	}
}

// A failure of the move leaves neither a mount nor a directory.
func TestFailedMoveLeavesNothing(t *testing.T) {
	r, c := newRig(t), config(t)
	boom := errors.New("busy")
	r.fail["move"] = boom
	err := Run(c, r.ops())
	if !errors.Is(err, boom) || slices.Contains(r.calls, "drop") || slices.Contains(r.calls, "exec") {
		t.Fatalf("%v %v", err, r.calls)
	}
	for _, n := range r.layers {
		if n != 0 {
			t.Errorf("layers left: %v", r.layers)
		}
	}
	ents, _ := os.ReadDir(c.BaseDir)
	if len(ents) != 0 {
		t.Errorf("left in the base directory: %v", ents)
	}
}

// A credential file is judged by the descriptor it was opened as: a symbolic
// link, a pipe (no wait for a writer) and a directory are all refused.
func TestCredentialSourceMustBeARegularFile(t *testing.T) {
	src := t.TempDir()
	target := filepath.Join(t.TempDir(), "t")
	os.WriteFile(target, []byte("x"), 0o600)
	os.Symlink(target, filepath.Join(src, "link"))
	if err := syscall.Mkfifo(filepath.Join(src, "pipe"), 0o600); err != nil {
		t.Skip(err)
	}
	os.Mkdir(filepath.Join(src, "dir"), 0o700)
	for _, name := range []string{"link", "pipe", "dir"} {
		if _, err := readLimited(filepath.Join(src, name)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}

	// whatever the path says, the handle decides
	old := openSource
	defer func() { openSource = old }()
	openSource = func(string) (*os.File, error) { return os.Open(src) }
	good := filepath.Join(t.TempDir(), "good")
	os.WriteFile(good, []byte("x"), 0o600)
	if _, err := readLimited(good); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("a directory handle was read: %v", err)
	}
	openSource = old
	if b, err := readLimited(good); err != nil || string(b) != "x" {
		t.Errorf("%q %v", b, err)
	}
}
