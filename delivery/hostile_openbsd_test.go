package delivery

// VM tests of the root-side kill and of the exclusive ownership of a user: a
// target that defends itself, two instances for one user, the process table.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// hostileMain is a daemon that defends itself: it signals every process of its
// user it can reach, in a loop, with SIGKILL ("kill") or SIGSTOP ("stop"). It
// never signals itself, so it is the one process that stays, and every killer
// that runs as its user dies or stops before it has done anything.
func hostileMain(args []string) {
	sig := unix.SIGKILL
	if len(args) > 0 && args[0] == "stop" {
		sig = unix.SIGSTOP
	}
	go func() {
		for {
			_ = unix.Kill(-1, sig)
		}
	}()
	fmt.Println("ready")
	time.Sleep(300 * time.Second)
	os.Exit(0)
}

func startHostile(t *testing.T, mode string) int {
	t.Helper()
	cmd := exec.Command(testExe(), "__hostile", mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: testUID, Gid: testGID}}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cmd.Wait() }()
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatalf("hostile: %q %v", line, err)
	}
	return pid
}

// R1: a target that kills or stops everything of its user that it can reach
// does not outlive Release, and Release does not report success while it lives.
func TestReleaseKillsATargetThatDefendsItself(t *testing.T) {
	for _, mode := range []string{"kill", "stop"} {
		t.Run(mode, func(t *testing.T) {
			base := needRoot(t)
			d, err := Prepare(context.Background(), testConfig(t, base, "svc", Credential{"a", []byte("x")}))
			if err != nil {
				t.Fatal(err)
			}
			hostile := startHostile(t, mode)
			if err := d.Release(); err != nil {
				t.Fatalf("Release: %v", err)
			}
			eventually(t, "the hostile target is gone", func() bool { return !alive(hostile) })
			if busy, err := UIDBusy(testUID); err != nil || busy {
				t.Fatalf("the user still has processes: %v %v", busy, err)
			}
			if mounted(d.Dir) {
				t.Fatal("still mounted")
			}
		})
	}
}

// The same when the owner is killed: nobody asks the helper, and it finishes.
func TestOwnerSIGKILLKillsATargetThatDefendsItself(t *testing.T) {
	base := needRoot(t)
	o, msg := startOwner(t, base, "svc")
	if o == nil {
		t.Fatal(msg)
	}
	// The owner's daemon is a target process too; the hostile joins it.
	hostile := startHostile(t, "kill")
	if err := o.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = o.cmd.Process.Wait()
	eventually(t, "the hostile target is gone", func() bool { return !alive(hostile) })
	eventually(t, "unmounted", func() bool { return !mounted(filepath.Join(base, "svc")) })
	eventually(t, "helper gone", func() bool { return !alive(o.helper) })
}

func TestKillUIDDefeatsAHostileTarget(t *testing.T) {
	needRoot(t)
	hostile := startHostile(t, "kill")
	if err := KillUID(testExe(), testUID, testGID, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the hostile target is gone", func() bool { return !alive(hostile) })
}

// The process table reads as the kernel's: this process is in it, and so is a
// process of another user under its real uid.
func TestProcessTableListsProcesses(t *testing.T) {
	needRoot(t)
	if err := checkProcLayout(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testExe(), "__sleeper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUID, Gid: testGID}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	ps, err := listUID(testUID)
	if err != nil || len(ps) != 1 || ps[0].pid != cmd.Process.Pid {
		t.Fatalf("processes of uid %d: %v %v, want [%d]", testUID, ps, err, cmd.Process.Pid)
	}
	if err := VerifyOnlyProcess(testUID, cmd.Process.Pid); err != nil {
		t.Fatal(err)
	}
	other := exec.Command(testExe(), "__sleeper")
	other.SysProcAttr = cmd.SysProcAttr
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Process.Kill(); _ = other.Wait() }()
	if err := VerifyOnlyProcess(testUID, cmd.Process.Pid); !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("a second process of the user: %v", err)
	}
}

// R2: the helper holds the lock of the user: a second service for the same user
// is refused while the first delivery lives, even when its owner let go.
func TestHelperHoldsTheUserLock(t *testing.T) {
	base := needRoot(t)
	c := testConfig(t, base, "svc", Credential{"a", []byte("x")})
	d, err := Prepare(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Release()
	c.UIDLock.Close()
	if l, err := AcquireUIDLock(base, testUID); !errors.Is(err, ErrBusy) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("a second service took the user while the helper lives: %v", err)
	}
	if err := d.Release(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the user lock is free once the helper is gone", func() bool {
		l, err := AcquireUIDLock(base, testUID)
		if err == nil {
			l.Close()
		}
		return err == nil
	})
}

// R2: a second service for the same user cannot even get as far as Prepare.
func TestTwoServicesOneUserSecondIsRefused(t *testing.T) {
	base := needRoot(t)
	first := testConfig(t, base, "one", Credential{"a", []byte("x")})
	d, err := Prepare(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Release()
	l, err := AcquireLock(base, "two")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if ul, err := AcquireUIDLock(base, testUID); !errors.Is(err, ErrBusy) {
		if ul != nil {
			ul.Close()
		}
		t.Fatalf("got %v, want ErrBusy", err)
	}
}

// R2: Prepare without the user lock is refused, before anything is started.
func TestPrepareRefusesWithoutTheUserLock(t *testing.T) {
	base := needRoot(t)
	c := testConfig(t, base, "svc", Credential{"a", []byte("x")})
	c.UIDLock = nil
	if _, err := Prepare(context.Background(), c); !errors.Is(err, ErrNoUIDLock) {
		t.Fatalf("got %v", err)
	}
	if mounted(filepath.Join(base, "svc")) {
		t.Fatal("mounted")
	}
}

// fdProbeMain: with three descriptors passed, makes the helper's call and
// reports which of 3, 4 and 5 would survive an exec.
func fdProbeMain() {
	closeOnExecInherited()
	var b strings.Builder
	for fd := 3; fd <= 5; fd++ {
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		fmt.Fprintf(&b, " %d:%v", fd, err == nil && flags&unix.FD_CLOEXEC != 0)
	}
	fmt.Println(strings.TrimSpace(b.String()))
}

// R5: the helper's control socket and both locks do not cross an exec.
func TestHelperDescriptorsAreCloseOnExec(t *testing.T) {
	var files []*os.File
	for i := 0; i < 3; i++ {
		f, err := os.Open("/dev/null")
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		files = append(files, f)
	}
	cmd := exec.Command(os.Args[0], "__fdprobe")
	cmd.ExtraFiles = files
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(string(out)); got != "3:true 4:true 5:true" {
		t.Fatalf("descriptors after the call: %q", got)
	}
}
