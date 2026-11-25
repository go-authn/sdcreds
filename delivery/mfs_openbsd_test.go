package delivery

// These tests mount real memory file systems: they run as root on OpenBSD (the
// CI lane runs them in a VM) and skip elsewhere. The test binary is its own
// helper and its own "owner" process, so SIGKILL of the owner can be tested.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const testUID, testGID = 32001, 32001

// exeEnv names the copy of the test binary that the target user can execute: it
// is the program that embeds the package (the helper, the killer, the daemon).
const exeEnv = "SDC_TEST_EXE"

func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case HelperCommand:
			if err := ServeMFS(os.Args[2:], os.NewFile(3, "ctl")); err != nil {
				fmt.Fprintln(os.Stderr, "helper:", err)
				os.Exit(1)
			}
			os.Exit(0)
		case KillCommand:
			os.Exit(KillMain(os.Args[2:]))
		case "__owner":
			ownerMain(os.Args[2:])
			os.Exit(0)
		case "__daemon":
			daemonMain()
		case "__sleeper":
			time.Sleep(300 * time.Second)
			os.Exit(0)
		}
	}
	if os.Geteuid() == 0 && os.Getenv(exeEnv) == "" {
		// A directory the target can search, holding a copy of this binary.
		dir, err := os.MkdirTemp("/var/run", "sdctestbin")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		self, err := os.ReadFile(os.Args[0])
		if err == nil {
			err = os.Chmod(dir, 0o755)
		}
		if err == nil {
			err = os.WriteFile(filepath.Join(dir, "exe"), self, 0o755)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Setenv(exeEnv, filepath.Join(dir, "exe"))
		code := m.Run()
		os.RemoveAll(dir)
		os.Exit(code)
	}
	os.Exit(m.Run())
}

// daemonMain is the "daemon": it starts a copy of itself in a session of its own
// (as a daemon that calls setsid does), prints that process's pid, and sleeps.
func daemonMain() {
	cmd := exec.Command(os.Args[0], "__sleeper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		fmt.Println("error", err)
		os.Exit(1)
	}
	fmt.Println(cmd.Process.Pid)
	time.Sleep(300 * time.Second)
	os.Exit(0)
}

func fakeDecrypt(name string, sealed []byte) ([]byte, error) {
	return append([]byte(nil), sealed...), nil
}

func testExe() string { return os.Getenv(exeEnv) }

// testConfig holds the service lock, as the caller of Prepare does; the lock
// goes with the test.
func testConfig(t testing.TB, base, name string, creds ...Credential) Config {
	t.Helper()
	if err := EnsureBase(base); err != nil {
		t.Fatal(err)
	}
	l, err := AcquireLock(base, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return Config{Base: base, Name: name, UID: testUID, GID: testGID, Creds: creds, Decrypt: fakeDecrypt, Lock: l, Executable: testExe()}
}

// ownerMain: owner <base> <name> [memlock]. It prepares a delivery, starts a
// daemon as the target user in a process group of its own, guards the group,
// prints "ready <daemon pid> <helper pid> <pid of the daemon's detached child>"
// and waits for ever. The daemon's child is in a session of its own: a kill by
// process group does not reach it.
func ownerMain(args []string) {
	base, name := args[0], args[1]
	if len(args) > 2 && args[2] == "memlock" {
		_ = unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{Cur: 64 << 10, Max: 64 << 10})
	}
	l, err := AcquireLock(base, name)
	if err != nil {
		fmt.Println("error false", err)
		return
	}
	d, err := Prepare(context.Background(), Config{Base: base, Name: name, UID: testUID, GID: testGID,
		Creds: []Credential{{"smtp-password", []byte("hunter2")}}, Decrypt: fakeDecrypt, Lock: l, Executable: testExe()})
	if err != nil {
		fmt.Println("error", errors.Is(err, ErrMemLock), err)
		return
	}
	cmd := exec.Command(testExe(), "__daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Credential: &syscall.Credential{Uid: testUID, Gid: testGID}}
	out, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Println("error false", err)
		return
	}
	if err := cmd.Start(); err != nil {
		fmt.Println("error false", err)
		return
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		fmt.Println("error false", err)
		return
	}
	if err := d.GuardGroup(cmd.Process.Pid); err != nil {
		fmt.Println("error false", err)
		return
	}
	fmt.Println("ready", cmd.Process.Pid, d.impl.pid, strings.TrimSpace(line))
	select {}
}

func needRoot(t *testing.T) string {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	// /tmp is sticky and world-writable, which EnsureBase refuses.
	base, err := os.MkdirTemp("/var/run", "sdctest")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = Sweep(base); _ = os.RemoveAll(base) })
	return base
}

func mounted(dir string) bool {
	var st unix.Statfs_t
	return unix.Statfs(dir, &st) == nil && isOurs(&st) && cstr(st.F_mntonname[:]) == dir
}

func alive(pid int) bool { return unix.Kill(pid, 0) == nil }

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if ok() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("still not true after 5 s: %s", what)
}

func TestPrepareAndRelease(t *testing.T) {
	base := needRoot(t)
	d, err := Prepare(context.Background(), testConfig(t, base, "svc", Credential{"smtp-password", []byte("hunter2")}, Credential{"empty", nil}))
	if err != nil {
		t.Fatal(err)
	}
	if d.Dir != filepath.Join(base, "svc") || !mounted(d.Dir) {
		t.Fatalf("not mounted at %s", d.Dir)
	}
	var st unix.Stat_t
	if err := unix.Stat(d.Dir, &st); err != nil || st.Mode&0o777 != 0o500 || int(st.Uid) != testUID || int(st.Gid) != testGID {
		t.Fatalf("dir: %v %o %d:%d", err, st.Mode&0o777, st.Uid, st.Gid)
	}
	b, err := os.ReadFile(filepath.Join(d.Dir, "smtp-password"))
	if err != nil || string(b) != "hunter2" {
		t.Fatalf("content %q %v", b, err)
	}
	if err := unix.Stat(filepath.Join(d.Dir, "smtp-password"), &st); err != nil || st.Mode&0o777 != 0o400 || int(st.Uid) != testUID {
		t.Fatalf("file: %v %o %d", err, st.Mode&0o777, st.Uid)
	}
	if err := os.WriteFile(filepath.Join(d.Dir, "new"), []byte("x"), 0o600); !errors.Is(err, unix.EROFS) {
		t.Fatalf("write on the mount: %v (want EROFS)", err)
	}
	var sf unix.Statfs_t
	if err := unix.Statfs(d.Dir, &sf); err != nil || sf.F_flags&unix.MNT_RDONLY == 0 || sf.F_flags&unix.MNT_NOEXEC == 0 || sf.F_flags&unix.MNT_NOSUID == 0 || sf.F_flags&unix.MNT_NODEV == 0 {
		t.Fatalf("flags %#x %v", sf.F_flags, err)
	}
	pid := d.impl.pid
	if err := d.Release(); err != nil {
		t.Fatal(err)
	}
	if err := d.Release(); err != nil {
		t.Fatal("second Release:", err)
	}
	if mounted(d.Dir) {
		t.Fatal("still mounted")
	}
	if _, err := os.Stat(d.Dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("directory remains: %v", err)
	}
	eventually(t, "helper gone", func() bool { return !alive(pid) })
}

func TestPrepareRefusesExistingDir(t *testing.T) {
	base := needRoot(t)
	if err := os.Mkdir(filepath.Join(base, "svc"), 0o700); err != nil {
		t.Fatal(err)
	}
	_, err := Prepare(context.Background(), testConfig(t, base, "svc"))
	if !errors.Is(err, ErrDirExists) {
		t.Fatalf("got %v", err)
	}
}

func TestCancelDuringPrepareLeavesNothing(t *testing.T) {
	base := needRoot(t)
	ctx, cancel := context.WithCancel(context.Background())
	c := testConfig(t, base, "svc", Credential{"a", []byte("x")})
	spawn := defaultSpawn(testExe())
	c.SpawnHelper = func(argv []string, files []*os.File) (int, error) {
		pid, err := spawn(argv, files)
		cancel()
		return pid, err
	}
	_, err := Prepare(ctx, c)
	t.Logf("Prepare: %v", err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
	_, e0 := os.Stat(filepath.Join(base, "svc"))
	t.Logf("after Prepare: mounted=%v stat=%v", mounted(filepath.Join(base, "svc")), e0)
	eventually(t, "nothing mounted or left", func() bool {
		_, e := os.Stat(filepath.Join(base, "svc"))
		return !mounted(filepath.Join(base, "svc")) && errors.Is(e, os.ErrNotExist)
	})
}

type owner struct {
	cmd      *exec.Cmd
	sleepPID int
	helper   int
	detached int // a process of the daemon that left its process group
}

func startOwner(t *testing.T, base, name string, extra ...string) (*owner, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"__owner", base, name}, extra...)...)
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatalf("owner: %v", err)
	}
	f := strings.Fields(line)
	if len(f) != 4 || f[0] != "ready" {
		return nil, strings.TrimSpace(line)
	}
	sp, _ := strconv.Atoi(f[1])
	hp, _ := strconv.Atoi(f[2])
	dp, _ := strconv.Atoi(f[3])
	t.Cleanup(func() {
		_ = unix.Kill(sp, unix.SIGKILL)
		_ = unix.Kill(hp, unix.SIGKILL)
		_ = unix.Kill(dp, unix.SIGKILL)
	})
	return &owner{cmd, sp, hp, dp}, ""
}

// The decision of the design (Q10): when the owner is killed, the daemon dies
// with it, and the mount goes.
func TestOwnerSIGKILLKillsDaemonAndUnmounts(t *testing.T) {
	base := needRoot(t)
	o, msg := startOwner(t, base, "svc")
	if o == nil {
		t.Fatal(msg)
	}
	dir := filepath.Join(base, "svc")
	if !mounted(dir) || !alive(o.sleepPID) {
		t.Fatal("setup")
	}
	if err := o.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = o.cmd.Process.Wait()
	eventually(t, "daemon killed", func() bool { return !reaped(o.sleepPID) })
	// The daemon's child called setsid: it is in no group of the daemon's. It dies
	// too, because the helper kills by user, not by group.
	eventually(t, "the process that left the group is killed", func() bool { return !reaped(o.detached) })
	eventually(t, "unmounted", func() bool { return !mounted(dir) })
	eventually(t, "helper gone", func() bool { return !alive(o.helper) })
}

// On a normal end too: Release kills what the program left behind before the
// credentials go.
func TestReleaseKillsWhatTheProgramLeftBehind(t *testing.T) {
	base := needRoot(t)
	d, err := Prepare(context.Background(), testConfig(t, base, "svc", Credential{"a", []byte("x")}))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(testExe(), "__daemon")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: &syscall.Credential{Uid: testUID, Gid: testGID}}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(out).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	child, _ := strconv.Atoi(strings.TrimSpace(line))
	t.Cleanup(func() { _ = unix.Kill(child, unix.SIGKILL) })
	go func() { _ = cmd.Wait() }()
	if !alive(child) {
		t.Fatal("setup")
	}
	if err := d.Release(); err != nil {
		t.Fatal(err)
	}
	if alive(child) && !isZombieGone(child) {
		t.Fatal("a process of the target survived Release")
	}
	if alive(cmd.Process.Pid) && !isZombieGone(cmd.Process.Pid) {
		t.Fatal("the daemon survived Release")
	}
}

// isZombieGone gives init a moment to reap what was killed.
func isZombieGone(pid int) bool {
	for i := 0; i < 100; i++ {
		if !alive(pid) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// A user that already has processes is refused: the delivery would kill them.
func TestPrepareRefusesAUserThatHasProcesses(t *testing.T) {
	base := needRoot(t)
	cmd := exec.Command(testExe(), "__sleeper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: testUID, Gid: testGID}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	_, err := Prepare(context.Background(), testConfig(t, base, "svc", Credential{"a", []byte("x")}))
	if !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("got %v, want ErrUIDBusy", err)
	}
	if mounted(filepath.Join(base, "svc")) {
		t.Fatal("mounted for a user that has processes")
	}
	if !alive(cmd.Process.Pid) {
		t.Fatal("the refusal killed a process")
	}
}

// The killer refuses to run as root: kill(-1) there is every process.
func TestKillMainRefusesRoot(t *testing.T) {
	needRoot(t)
	if got := KillMain([]string{"kill"}); got != killExitUsage {
		t.Fatalf("KillMain as root returned %d", got)
	}
}

// A mount unmounted from outside takes what runs on it down, and the helper
// leaves; nothing is left to serve.
func TestOutsideUnmountKillsTheTarget(t *testing.T) {
	base := needRoot(t)
	o, msg := startOwner(t, base, "svc")
	if o == nil {
		t.Fatal(msg)
	}
	dir := filepath.Join(base, "svc")
	if err := unix.Unmount(dir, unix.MNT_FORCE); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the daemon is killed", func() bool { return !reaped(o.sleepPID) })
	eventually(t, "the process that left the group is killed", func() bool { return !reaped(o.detached) })
	eventually(t, "helper gone", func() bool { return !alive(o.helper) })
}

// The helper holds the service lock: the owner that closes it, or loses it, does
// not let a second instance start while a helper still holds a mount.
func TestHelperHoldsTheServiceLock(t *testing.T) {
	base := needRoot(t)
	c := testConfig(t, base, "svc", Credential{"a", []byte("x")})
	d, err := Prepare(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Release()
	c.Lock.Close()
	if l, err := AcquireLock(base, "svc"); !errors.Is(err, ErrBusy) {
		if l != nil {
			l.Close()
		}
		t.Fatalf("a second instance took the lock while the helper lives: %v", err)
	}
	if err := d.Release(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the lock is free once the helper is gone", func() bool {
		l, err := AcquireLock(base, "svc")
		if err == nil {
			l.Close()
		}
		return err == nil
	})
}

// A mount that is not empty is refused: the image is empty, and something there
// was not put there by this process.
func TestVerifyEmptyRefusesWhatIsThere(t *testing.T) {
	base := needRoot(t)
	fd, err := unix.Open(base, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := verifyEmpty(fd); err != nil {
		t.Fatalf("empty directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(base, "x"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyEmpty(fd); !errors.Is(err, ErrMount) {
		t.Fatalf("a directory with a file: %v", err)
	}
}

// reaped is false once the process is gone or a zombie: kill(0) succeeds on a
// zombie and the daemon is a grandchild of nobody here, init reaps it.
func reaped(pid int) bool { return alive(pid) }

func TestHelperKilledClosesLostAndUnmounts(t *testing.T) {
	base := needRoot(t)
	d, err := Prepare(context.Background(), testConfig(t, base, "svc", Credential{"a", []byte("x")}))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Release()
	if err := unix.Kill(d.impl.pid, unix.SIGKILL); err != nil {
		t.Fatal(err)
	}
	select {
	case <-d.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("Lost never closed")
	}
	eventually(t, "unmounted by the kernel", func() bool { return !mounted(d.Dir) })
}

func TestStaleMountIsSwept(t *testing.T) {
	base := needRoot(t)
	o, msg := startOwner(t, base, "stale")
	if o == nil {
		t.Fatal(msg)
	}
	dir := filepath.Join(base, "stale")
	// A helper that cannot run, and an owner that is gone: the mount stays.
	if err := unix.Kill(o.helper, unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	_ = o.cmd.Process.Kill()
	_, _ = o.cmd.Process.Wait()
	if !mounted(dir) {
		t.Skip("the mount went with the owner; nothing to sweep")
	}
	if err := os.Mkdir(filepath.Join(base, "leftover"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A stopped helper cannot serve the unmount: Sweep gives up, it does not hang.
	unmountTimeout = time.Second
	defer func() { unmountTimeout = 10 * time.Second }()
	if _, err := Sweep(base); !errors.Is(err, ErrWedged) {
		t.Fatalf("a stopped helper: got %v, want ErrWedged", err)
	}
	if err := unix.Kill(o.helper, unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the helper serves the pending unmount", func() bool { return !mounted(dir) })
	sw, err := Sweep(base)
	if err != nil {
		t.Fatal(err)
	}
	if mounted(dir) {
		t.Fatalf("still mounted after Sweep %v", sw)
	}
	for _, n := range []string{"stale", "leftover"} {
		if _, err := os.Stat(filepath.Join(base, n)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains: %v", n, err)
		}
	}
	_ = unix.Kill(o.helper, unix.SIGKILL)
}

func TestMemLockFailureRefuses(t *testing.T) {
	base := needRoot(t)
	o, msg := startOwner(t, base, "svc", "memlock")
	if o != nil {
		t.Fatal("a 64 KiB memlock limit must refuse")
	}
	if !strings.HasPrefix(msg, "error true") {
		t.Fatalf("want ErrMemLock, got %q", msg)
	}
	if mounted(filepath.Join(base, "svc")) {
		t.Fatal("mounted without locked memory")
	}
}

func TestSweepServiceOnlyTouchesItsService(t *testing.T) {
	base := needRoot(t)
	for _, n := range []string{"a", "b"} {
		if err := os.Mkdir(filepath.Join(base, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SweepService(base, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "b")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(base, "a")); err == nil {
		t.Fatal("a remains")
	}
	if _, err := SweepService(base, "../x"); !errors.Is(err, ErrBadService) {
		t.Fatalf("got %v", err)
	}
}

// The capacities the class table promises are what a mounted image really
// offers: pickClass trusts them.
func TestClassCapacities(t *testing.T) {
	base := needRoot(t)
	for _, cl := range classes {
		dir := filepath.Join(base, fmt.Sprintf("c%d", cl.MiB))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		mine, theirs := os.NewFile(uintptr(fds[0]), "m"), os.NewFile(uintptr(fds[1]), "t")
		a := helperArgs{Owner: os.Getpid(), Dir: dir, MiB: cl.MiB, UID: testUID, GID: testGID, Exe: testExe()}
		if _, err := defaultSpawn(testExe())(append([]string{HelperCommand}, a.argv()...), []*os.File{theirs}); err != nil {
			t.Fatal(err)
		}
		theirs.Close()
		line, err := bufio.NewReader(mine).ReadString('\n')
		if err != nil || line != "ready\n" {
			t.Fatalf("class %d: %q %v", cl.MiB, line, err)
		}
		var sf unix.Statfs_t
		if err := unix.Statfs(dir, &sf); err != nil {
			t.Fatal(err)
		}
		kb := int(uint64(sf.F_bavail) * uint64(sf.F_bsize) / 1024)
		t.Logf("class %d MiB: %d KiB, %d inodes (table: %d, %d)", cl.MiB, kb, sf.F_ffree, cl.DataKB, cl.Inodes)
		if kb < cl.DataKB || int(sf.F_ffree) < cl.Inodes {
			t.Errorf("class %d MiB offers %d KiB and %d inodes, the table promises %d and %d", cl.MiB, kb, sf.F_ffree, cl.DataKB, cl.Inodes)
		}
		_, _ = mine.Write([]byte("release\n"))
		_, _ = bufio.NewReader(mine).ReadString('\n')
		mine.Close()
	}
}
