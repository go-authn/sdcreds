//go:build linux

package s6

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const jailHelperEnv = "SDCREDS_S6_JAIL_HELPER"

// TestJailHelper is the child of TestTheRootDirectorySurvivesSetns. It sits in
// a chroot, as a launcher thread does when s6-run runs in one, and joins the
// mount namespace it already is in.
func TestJailHelper(t *testing.T) {
	jail := os.Getenv(jailHelperEnv)
	if jail == "" {
		t.Skip("child of TestTheRootDirectorySurvivesSetns")
	}
	runtime.LockOSThread()
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatal(err)
	}
	ns, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chroot(jail); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Chdir("/"); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenFile("/", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	broken, err := os.OpenFile("/", os.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	broken.Close()

	done := make(chan error)
	go func() {
		runtime.LockOSThread() // ends with the goroutine, as the launcher does
		if err := syscall.Unshare(syscall.CLONE_FS); err != nil {
			done <- err
			return
		}
		if err := enterNamespace(ns, root, "/"); err != nil {
			done <- err
			return
		}
		if _, err := os.Stat("/jail-marker"); err != nil {
			t.Errorf("the root is not the jail any more: %v", err)
		}
		if _, err := os.Stat("/proc"); err == nil {
			t.Errorf("the host tree is visible from the launcher: /proc exists")
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// A root that cannot be put back is an error, and says so.
	go func() {
		runtime.LockOSThread()
		if err := syscall.Unshare(syscall.CLONE_FS); err != nil {
			done <- err
			return
		}
		done <- enterNamespace(ns, broken, "/")
	}()
	if err := <-done; err == nil || !strings.Contains(err.Error(), "root directory") {
		t.Fatalf("a root that cannot be restored was accepted: %v", err)
	}
}

// setns resets the root directory of the thread to the root of the namespace:
// the service of an s6-run that runs inside a chroot must keep that root.
func TestTheRootDirectorySurvivesSetns(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	jail := t.TempDir()
	if err := os.Chmod(jail, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(jail, "jail-marker"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestJailHelper$", "-test.v")
	cmd.Env = append(os.Environ(), jailHelperEnv+"="+jail)
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestJailHelper") {
		t.Fatalf("%v\n%s", err, out)
	}
}

// onThread runs f on a thread of its own that is never given back: whatever f
// does to the attributes of the thread ends with it.
func onThread(f func()) {
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		f()
	}()
	<-done
}

func needRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
}

// Every step of getting the launcher thread ready is a refusal: a thread that
// cannot join the namespace, put back its root or its directory, or be
// restricted starts nothing, and a child that did not take the identity is
// killed and reported.
func TestLaunchRefusals(t *testing.T) {
	needRoot(t)
	u := User{UID: 12345, GID: 12345}
	open := func(p string) *os.File {
		f, err := os.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	try := func(ns, root *os.File, wd string) (err error) {
		onThread(func() {
			if ns == nil {
				ns = open("/proc/thread-self/ns/mnt")
			}
			_, err = launch(ns, root, wd, u, "/bin/true", []string{"/bin/true"}, nil)
		})
		return err
	}
	closed := open("/")
	closed.Close()
	rootDir := open("/")
	if err := try(closed, rootDir, "/"); err == nil || !strings.Contains(err.Error(), "setns") {
		t.Errorf("a namespace that cannot be joined: %v", err)
	}
	if err := try(nil, open("/etc/passwd"), "/"); err == nil || !strings.Contains(err.Error(), "root directory") {
		t.Errorf("a root that is not a directory: %v", err)
	}
	if err := try(nil, rootDir, "/nonexistent"); err == nil {
		t.Error("a working directory that does not exist")
	}
	oldRestrict, oldJudge, oldChroot := restrict, judgeChild, chroot
	defer func() { restrict, judgeChild, chroot = oldRestrict, oldJudge, oldChroot }()
	chroot = func(string) error { return errors.New("boom") }
	if err := try(nil, rootDir, "/"); err == nil || !strings.Contains(err.Error(), "root directory") {
		t.Errorf("a thread that cannot chroot: %v", err)
	}
	chroot = oldChroot
	restrict = func() error { return errors.New("boom") }
	if err := try(nil, rootDir, "/"); err == nil || !strings.Contains(err.Error(), "restrict") {
		t.Errorf("a thread that cannot be restricted: %v", err)
	}
	restrict = oldRestrict
	judgeChild = func(string, User) error { return errors.New("root left") }
	if err := try(nil, rootDir, "/"); err == nil || !strings.Contains(err.Error(), "did not take the identity") {
		t.Errorf("a child that kept root: %v", err)
	}
}

func TestStartRefusals(t *testing.T) {
	needRoot(t)
	u := User{UID: 12345, GID: 12345}
	try := func(argv ...string) (err error) {
		onThread(func() { _, err = start(u, argv, nil) })
		return err
	}
	if err := try("/nonexistent/program"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a missing program: %v", err)
	}
	// Not a program, though executable by its mode: the failed exec is the
	// error of start.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	notProg := filepath.Join(dir, "text")
	if err := os.WriteFile(notProg, []byte("not a program\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := try(notProg); err == nil {
		t.Error("a file that is not a program was started")
	}
	oldNS := openNS
	openNS = func() (*os.File, error) { return nil, errors.New("boom") }
	if err := try("/bin/true"); err == nil || err.Error() != "boom" {
		t.Errorf("no namespace to join: %v", err)
	}
	openNS = oldNS
	old := openRoot
	defer func() { openRoot = old }()
	openRoot = func() (*os.File, error) { return nil, errors.New("boom") }
	if err := try("/bin/true"); err == nil || !strings.Contains(err.Error(), "cannot save the root") {
		t.Errorf("no root to save: %v", err)
	}
}

func TestExitOutcome(t *testing.T) {
	run := func(script string) error { return exec.Command("/bin/sh", "-c", script).Run() }
	for _, c := range []struct {
		script string
		want   outcome
	}{{"exit 0", outcome{}}, {"exit 3", outcome{code: 3}}, {"kill -KILL $$", outcome{code: 128 + 9}}, {"kill -TERM $$", outcome{code: 128 + 15}}} {
		if got := exitOutcome(run(c.script)); got != c.want {
			t.Errorf("%s: %+v, want %+v", c.script, got, c.want)
		}
	}
	boom := errors.New("boom")
	if got := exitOutcome(boom); got.err != boom || got.code != 0 {
		t.Errorf("%+v", got)
	}
}
