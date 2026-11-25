//go:build openbsd

package main

// These tests drive the real `sdcreds` binary (SDCREDS_BIN, installed where an
// unprivileged user can execute it) as root, on an OpenBSD machine: a real mount,
// the daemon's exit, SIGKILL of sdcreds, a leftover swept at start, and the
// refusals that must happen before a key is read. They skip elsewhere.

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/delivery"
)

const targetUser = "nobody"

var fixedMachineID = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

type vmEnv struct {
	t                   *testing.T
	bin, dir, base, src string
	key, mid, prog      string
	machineID           [16]byte
	useHWUUID           bool
}

func newVM(t *testing.T) *vmEnv {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	bin := os.Getenv("SDCREDS_BIN")
	if bin == "" {
		t.Skip("SDCREDS_BIN names the sdcreds binary to drive")
	}
	dir, err := os.MkdirTemp("/var/run", "sdcrun")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		delivery.Sweep(filepath.Join(dir, "base"))
		os.RemoveAll(dir)
	})
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	e := &vmEnv{t: t, bin: bin, dir: dir, base: filepath.Join(dir, "base"), src: filepath.Join(dir, "src"),
		key: filepath.Join(dir, "host.key"), mid: filepath.Join(dir, "mid"), prog: filepath.Join(dir, "prog"), machineID: fixedMachineID}
	if err := os.Mkdir(e.src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.mid, []byte(hex.EncodeToString(e.machineID[:])+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.hostKey(0o600)
	e.seal("smtp-password", "hunter2")
	return e
}

var hostKeyData []byte

func (e *vmEnv) hostKey(mode os.FileMode) {
	e.t.Helper()
	os.Remove(e.key)
	data, err := sdcreds.CreateHostKey(e.key, e.machineID)
	if err != nil {
		e.t.Fatal(err)
	}
	hostKeyData = data
	if err := os.Chmod(e.key, mode); err != nil {
		e.t.Fatal(err)
	}
}

func (e *vmEnv) seal(name, secret string) {
	e.t.Helper()
	blob, err := sdcreds.Encrypt([]byte(secret), sdcreds.EncryptOptions{Key: sdcreds.IDHost, HostKey: sdcreds.StaticHostKey(hostKeyData), Name: name})
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.src, name), []byte(sdcreds.Armor(blob, 64)), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *vmEnv) program(body string) {
	e.t.Helper()
	if err := os.WriteFile(e.prog, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		e.t.Fatal(err)
	}
}

func (e *vmEnv) args(extra ...string) []string {
	a := []string{"run", "--service=web", "--user=" + targetUser, "--source=" + e.src, "--base=" + e.base, "--secret=" + e.key}
	if !e.useHWUUID {
		a = append(a, "--machine-id-file="+e.mid)
	}
	return append(append(a, extra...), "--", e.prog)
}

func (e *vmEnv) command(extra ...string) *exec.Cmd {
	return exec.Command(e.bin, e.args(extra...)...)
}

// result runs sdcreds to its end.
func (e *vmEnv) result(extra ...string) (stdout, stderr string, code int) {
	e.t.Helper()
	c := e.command(extra...)
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	err := c.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatal(err)
	}
	return o.String(), er.String(), code
}

// nothingMounted says no mount of ours is left under the base, whatever the
// state of the directory.
func (e *vmEnv) nothingMounted() {
	e.t.Helper()
	var n int
	for _, s := range sweepAll(e.t, e.base) {
		if s.Mounted {
			e.t.Errorf("a mount was left: %s", s.Dir)
		}
		n++
	}
	_ = n
}

func sweepAll(t *testing.T, base string) []delivery.Swept {
	t.Helper()
	sw, err := delivery.Sweep(base)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return sw
}

func alive(pid int) bool { return syscall.Kill(pid, 0) == nil }

func waitGone(t *testing.T, pid int) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if !alive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Errorf("process %d is still running", pid)
}

func TestRunDeliversAndReleases(t *testing.T) {
	e := newVM(t)
	e.program(`echo "$CREDENTIALS_DIRECTORY"; cat "$CREDENTIALS_DIRECTORY/smtp-password"; echo; id -u; ls -l "$CREDENTIALS_DIRECTORY/smtp-password"; echo x > "$CREDENTIALS_DIRECTORY/new" 2>/dev/null && echo WRITABLE; true`)
	so, se, code := e.result()
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, so, se)
	}
	for _, want := range []string{e.base + "/web\n", "hunter2\n", "-r--------"} {
		if !strings.Contains(so, want) {
			t.Errorf("stdout lacks %q:\n%s", want, so)
		}
	}
	if strings.Contains(so, "WRITABLE") {
		t.Error("the credential directory is writable")
	}
	nobody := strings.TrimSpace(strings.Split(so, "\n")[3])
	if nobody == "0" || nobody == "" {
		t.Errorf("the program ran as uid %q", nobody)
	}
	e.nothingMounted()
	if _, err := os.Stat(filepath.Join(e.base, "web", "smtp-password")); err == nil {
		t.Error("the credential is still readable after the program exited")
	}
}

func TestRunPassesTheExitStatus(t *testing.T) {
	e := newVM(t)
	e.program(`exit 7`)
	if _, _, code := e.result(); code != 7 {
		t.Errorf("exit %d, want 7", code)
	}
	e.program(`kill -TERM $$; sleep 5`)
	if _, _, code := e.result(); code != 128+int(syscall.SIGTERM) {
		t.Errorf("signalled program: exit %d, want %d", code, 128+int(syscall.SIGTERM))
	}
	e.nothingMounted()
}

// Q10: if sdcreds is killed with SIGKILL, the daemon is killed too and the
// credentials are unmounted.
func TestRunSIGKILLKillsTheDaemonAndUnmounts(t *testing.T) {
	e := newVM(t)
	e.program(`echo $$; cat "$CREDENTIALS_DIRECTORY/smtp-password"; echo; exec sleep 300`)
	c := e.command()
	out, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := out.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	for _, ch := range strings.SplitN(string(buf[:n]), "\n", 2)[0] {
		pid = pid*10 + int(ch-'0')
	}
	if pid < 2 || !alive(pid) {
		t.Fatalf("daemon pid %d not running", pid)
	}
	if err := syscall.Kill(c.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	c.Wait()
	waitGone(t, pid)
	if alive(pid) {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Fatal("the daemon survived the SIGKILL of sdcreds")
	}
	// the helper unmounts and exits; give it a moment, then nothing is mounted.
	var left []delivery.Swept
	for i := 0; i < 50; i++ {
		var st unix.Statfs_t
		if unix.Statfs(filepath.Join(e.base, "web"), &st) != nil || string(bytes.TrimRight(st.F_fstypename[:], "\x00")) != "mfs" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	left = sweepAll(t, e.base)
	for _, s := range left {
		if s.Mounted {
			t.Errorf("a mount was left after the SIGKILL: %s", s.Dir)
		}
	}
	// the lock died with sdcreds: the service can be started again.
	e.program(`exit 0`)
	if _, se, code := e.result(); code != 0 {
		t.Errorf("restart after SIGKILL: exit %d: %s", code, se)
	}
}

// A leftover directory and a stale lock file of a crashed run are swept at the
// next start, which then works.
func TestRunSweepsALeftover(t *testing.T) {
	e := newVM(t)
	if err := os.MkdirAll(e.base, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(e.base, "web"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.base, ".web.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	e.program(`cat "$CREDENTIALS_DIRECTORY/smtp-password"`)
	so, se, code := e.result()
	if code != 0 || so != "hunter2" || !strings.Contains(se, "swept a leftover") {
		t.Errorf("exit %d stdout %q stderr %q", code, so, se)
	}
}

func TestRunRefusesUID0BeforeAnyKey(t *testing.T) {
	e := newVM(t)
	// no host key at all: a refusal that read the key would say so instead.
	os.Remove(e.key)
	args := e.args()
	for i, a := range args {
		if strings.HasPrefix(a, "--user=") {
			args[i] = "--user=root"
		}
	}
	c := exec.Command(e.bin, args...)
	var se bytes.Buffer
	c.Stderr = &se
	err := c.Run()
	ee, _ := err.(*exec.ExitError)
	if ee == nil || ee.ExitCode() != exitRefused || !strings.Contains(se.String(), "uid 0") {
		t.Errorf("%v: %q", err, se.String())
	}
	if _, err := os.Stat(filepath.Join(e.base, "web")); err == nil {
		t.Error("a credential directory was made for uid 0")
	}
}

func TestRunRefusesAHostKeyThatIsNot0600(t *testing.T) {
	e := newVM(t)
	e.program(`cat "$CREDENTIALS_DIRECTORY/smtp-password"`)
	for _, m := range []os.FileMode{0o400, 0o640, 0o660, 0o644} {
		e.hostKey(m)
		so, se, code := e.result()
		if code != exitRefused || !(strings.Contains(se, "access mode") || strings.Contains(se, "writable by group or others")) || so != "" {
			t.Errorf("mode %v: exit %d stdout %q stderr %q", m, code, so, se)
		}
	}
	e.nothingMounted()
}

func TestRunRefusesABusyService(t *testing.T) {
	e := newVM(t)
	if err := delivery.EnsureBase(e.base); err != nil {
		t.Fatal(err)
	}
	l, err := delivery.AcquireLock(e.base, "web")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	e.program(`exit 0`)
	_, se, code := e.result()
	if code != exitRefused || !strings.Contains(se, "already running") {
		t.Errorf("exit %d: %s", code, se)
	}
}

func TestRunCheckStopsBeforeTheKey(t *testing.T) {
	e := newVM(t)
	os.Remove(e.key)
	e.program(`exit 0`)
	so, se, code := e.result("--check")
	if code != 0 || strings.TrimSpace(so) != "ok" {
		t.Errorf("exit %d %q %q", code, so, se)
	}
	if _, err := os.Stat(filepath.Join(e.base, "web")); err == nil {
		t.Error("--check made a directory")
	}
}

// R3: the machine id is hw.uuid when no file is given. Both branches run on every
// lane through the seam: a uuid that is there is the one used, one that is not
// refuses the run, and no other source is then consulted.
func withHWUUID(t *testing.T, f func() ([16]byte, error)) *int {
	t.Helper()
	old := hwUUID
	t.Cleanup(func() { hwUUID = old })
	calls := new(int)
	hwUUID = func() ([16]byte, error) { *calls++; return f() }
	return calls
}

func TestHostKeyUsesTheHardwareUUIDThatIsThere(t *testing.T) {
	e := newVM(t)
	calls := withHWUUID(t, func() ([16]byte, error) { return fixedMachineID, nil })
	got, err := openbsdHostKeyOrRefuse(e.key, "")
	if err != nil {
		t.Fatal(err)
	}
	want, err := openbsdHostKey(e.key, e.mid)
	if err != nil {
		t.Fatal(err)
	}
	if *calls != 1 || !bytes.Equal(got, want) || len(got) == 0 {
		t.Fatalf("the key from hw.uuid differs from the key of the same id in a file (%d calls)", *calls)
	}
	// The uuid is what binds the key: another one finds the key foreign.
	withHWUUID(t, func() ([16]byte, error) { return [16]byte{9, 9, 9}, nil })
	if _, err := openbsdHostKeyOrRefuse(e.key, ""); err == nil {
		t.Fatal("a key made for another machine id was accepted")
	}
	// An explicit file wins: hw.uuid is not even read.
	n := withHWUUID(t, func() ([16]byte, error) { return [16]byte{}, nil })
	if _, err := openbsdHostKey(e.key, e.mid); err != nil || *n != 0 {
		t.Fatalf("with --machine-id-file: %v, hw.uuid read %d times", err, *n)
	}
}

func TestHostKeyRefusesWithoutAHardwareUUID(t *testing.T) {
	e := newVM(t)
	calls := withHWUUID(t, func() ([16]byte, error) { return [16]byte{}, errors.New("sysctl hw.uuid: value is not available") })
	key, err := openbsdHostKeyOrRefuse(e.key, "")
	var rf *refusal
	if !errors.As(err, &rf) || key != nil || !strings.Contains(err.Error(), "hw.uuid") || *calls != 1 {
		t.Fatalf("got %v %v (%d calls)", key, err, *calls)
	}
	// An all-zero uuid is no id either.
	withHWUUID(t, func() ([16]byte, error) { return [16]byte{}, nil })
	if _, err := openbsdHostKeyOrRefuse(e.key, ""); !errors.As(err, &rf) {
		t.Fatalf("a null uuid was accepted: %v", err)
	}
}

// The real sysctl, where the machine has one (the CI VMs have none; a local VM
// does).
func TestRunUsesTheHardwareUUID(t *testing.T) {
	e := newVM(t)
	id, err := hwUUID()
	if err != nil {
		t.Skip("no hw.uuid on this machine: " + err.Error())
	}
	e.useHWUUID, e.machineID = true, id
	e.hostKey(0o600)
	e.seal("smtp-password", "from-uuid")
	e.program(`cat "$CREDENTIALS_DIRECTORY/smtp-password"`)
	if so, se, code := e.result(); code != 0 || so != "from-uuid" {
		t.Errorf("exit %d %q %q", code, so, se)
	}
}

// detachScript starts a process that leaves the program's process group and
// session, the way a daemon does, and prints its pid once it has done so (a pid
// printed earlier could be of a process still in the group).
const detachScript = `perl -MPOSIX -e 'POSIX::setsid() or die; $| = 1; print "$$\n"; exec "sleep", "300"' </dev/null 2>&1 &
`

// firstPIDs starts c and reads n pids, one per line, from its stdout.
func firstPIDs(t *testing.T, c *exec.Cmd, n int) []int {
	t.Helper()
	out, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(out)
	var pids []int
	for len(pids) < n && sc.Scan() {
		p, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
		if err != nil {
			t.Fatalf("not a pid: %q", sc.Text())
		}
		pids = append(pids, p)
	}
	if len(pids) != n {
		t.Fatalf("read %d pids, want %d", len(pids), n)
	}
	return pids
}

// B1: a daemon that leaves the group and the session still dies with sdcreds.
func TestRunSIGKILLKillsAProcessThatLeftTheSession(t *testing.T) {
	e := newVM(t)
	e.program(`echo $$
` + detachScript + `exec sleep 300`)
	c := e.command()
	pids := firstPIDs(t, c, 2)
	main, detached := pids[0], pids[1]
	t.Cleanup(func() { _ = syscall.Kill(detached, syscall.SIGKILL); _ = syscall.Kill(main, syscall.SIGKILL) })
	if !alive(detached) || !alive(main) {
		t.Fatal("setup: the program is not running")
	}
	if err := syscall.Kill(c.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = c.Wait()
	waitGone(t, main)
	waitGone(t, detached)
	e.nothingMounted()
}

// B1: on a normal end, what the program left behind dies before the credentials
// go.
func TestRunKillsWhatTheProgramLeftBehind(t *testing.T) {
	e := newVM(t)
	e.program(detachScript + `sleep 2
exit 0`)
	so, se, code := e.result()
	if code != 0 {
		t.Fatalf("exit %d: %s", code, se)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(so))
	if err != nil {
		t.Fatalf("stdout %q", so)
	}
	waitGone(t, pid)
	e.nothingMounted()
}

// R2: a user is owned by one delivery at a time, whatever the service and the
// base: a second service for it is refused at start, and the first goes on.
func TestRunRefusesASecondServiceForTheSameUser(t *testing.T) {
	e := newVM(t)
	e.program(`echo $$; exec sleep 300`)
	first := e.command()
	pids := firstPIDs(t, first, 1)
	t.Cleanup(func() { _ = syscall.Kill(pids[0], syscall.SIGKILL); _ = first.Process.Kill(); _ = first.Wait() })
	second := exec.Command(e.bin, "run", "--service=other", "--user="+targetUser, "--source="+e.src,
		"--base="+filepath.Join(e.dir, "base2"), "--secret="+e.key, "--machine-id-file="+e.mid, "--", e.prog)
	var se bytes.Buffer
	second.Stderr = &se
	err := second.Run()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || ee.ExitCode() != exitRefused {
		t.Fatalf("second service: %v: %s", err, se.String())
	}
	if !alive(pids[0]) {
		t.Fatal("the refusal killed the first service's program")
	}
	t.Cleanup(func() { delivery.Sweep(filepath.Join(e.dir, "base2")) })
}

// F1: the helper is gone: sdcreds kills the program and exits non-zero.
func TestRunFailsAndKillsWhenTheHelperIsGone(t *testing.T) {
	e := newVM(t)
	e.program(`echo $$
` + detachScript + `exec sleep 300`)
	c := e.command()
	var se bytes.Buffer
	c.Stderr = &se
	pids := firstPIDs(t, c, 2)
	main, detached := pids[0], pids[1]
	t.Cleanup(func() { _ = syscall.Kill(detached, syscall.SIGKILL); _ = syscall.Kill(main, syscall.SIGKILL) })
	// find the helper: a child of sdcreds that runs the helper command on this base.
	out, err := exec.Command("pgrep", "-f", delivery.HelperCommand+".*"+e.base).Output()
	if err != nil {
		t.Fatalf("no helper found: %v", err)
	}
	helper, err := strconv.Atoi(strings.Fields(string(out))[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(helper, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("sdcreds exited 0 after the delivery was lost")
		}
	case <-time.After(30 * time.Second):
		_ = c.Process.Kill()
		t.Fatal("sdcreds did not end after the helper was killed")
	}
	waitGone(t, main)
	waitGone(t, detached)
	if !strings.Contains(se.String(), "delivery lost") {
		t.Errorf("stderr does not say why: %q", se.String())
	}
	e.nothingMounted()
}

// The user that already has processes is refused, nothing is killed.
func TestRunRefusesATargetThatHasProcesses(t *testing.T) {
	e := newVM(t)
	pre := exec.Command("sleep", "300")
	u, err := user.Lookup(targetUser)
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	pre.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}}
	if err := pre.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pre.Process.Kill(); _ = pre.Wait() })
	e.program(`echo ran`)
	so, _, code := e.result()
	if code == 0 || strings.Contains(so, "ran") {
		t.Errorf("a busy target was served: exit %d %q", code, so)
	}
	if !alive(pre.Process.Pid) {
		t.Error("the refusal killed a process")
	}
}

// --class: the limits of the class reach the program, and nothing else of the
// class does. The class is a file of login.conf.d, which wins over login.conf.
func TestRunAppliesTheLimitsOfTheClass(t *testing.T) {
	e := newVM(t)
	const class = "sdcredstest"
	file := "/etc/login.conf.d/" + class
	if err := os.MkdirAll("/etc/login.conf.d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte(class+":\\\n\t:openfiles-cur=77:\\\n\t:openfiles-max=88:\\\n\t:coredumpsize=0:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(file) })
	e.program(`echo "soft $(ulimit -Sn) hard $(ulimit -Hn) core $(ulimit -Sc)"`)
	so, se, code := e.result("--class=" + class)
	if code != 0 || !strings.Contains(so, "soft 77 hard 88 core 0") {
		t.Errorf("exit %d stdout %q stderr %q", code, so, se)
	}
	// a class whose value cannot be read refuses before anything is mounted
	if err := os.WriteFile(file, []byte(class+":openfiles=lots:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	so, se, code = e.result("--class=" + class)
	if code == 0 || so != "" || !strings.Contains(se, "lots") {
		t.Errorf("a bad limit: exit %d stdout %q stderr %q", code, so, se)
	}
	e.nothingMounted()
	// a class file that anyone can write is refused
	if err := os.WriteFile(file, []byte(class+":openfiles=77:\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(file, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, code = e.result("--class=" + class); code == 0 {
		t.Error("a world-writable class file was used")
	}
}

// The program gets a short allow-listed environment.
func TestRunEnvironmentIsAllowListed(t *testing.T) {
	e := newVM(t)
	e.program(`env`)
	c := e.command()
	c.Env = []string{"PATH=/evil", "LD_LIBRARY_PATH=/evil", "SECRET_TOKEN=x", "LANG=C", "TERM=vt100", "HOME=/root"}
	var o, er bytes.Buffer
	c.Stdout, c.Stderr = &o, &er
	if err := c.Run(); err != nil {
		t.Fatalf("%v %s", err, er.String())
	}
	for _, bad := range []string{"/evil", "SECRET_TOKEN", "HOME=", "__SDCREDS"} {
		if strings.Contains(o.String(), bad) {
			t.Errorf("the program sees %q:\n%s", bad, o.String())
		}
	}
	for _, want := range []string{"LANG=C", "TERM=vt100", "CREDENTIALS_DIRECTORY=" + e.base + "/web"} {
		if !strings.Contains(o.String(), want) {
			t.Errorf("the program lacks %q:\n%s", want, o.String())
		}
	}
}

// `sdcreds sweep` removes a leftover without starting the service.
func TestSweepCommand(t *testing.T) {
	e := newVM(t)
	if err := os.MkdirAll(e.base, 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(e.base, "web"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.base, ".web.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(e.bin, "sweep", "--base="+e.base).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "swept "+e.base+"/web") {
		t.Fatalf("%v %s", err, out)
	}
	if _, err := os.Stat(filepath.Join(e.base, "web")); err == nil {
		t.Error("the leftover directory is still there")
	}
	out, err = exec.Command(e.bin, "sweep", "--base="+e.base).CombinedOutput()
	if err != nil || !strings.Contains(string(out), "nothing to sweep") {
		t.Errorf("second sweep: %v %s", err, out)
	}
}

// Unencrypted swap refuses the run; a variable the kernel does not have means
// swap is always encrypted; a read that fails refuses too.
func TestCheckSwapEncrypted(t *testing.T) {
	old := swapEncrypt
	defer func() { swapEncrypt = old }()
	swapEncrypt = func() (int, error) { return 1, nil }
	if err := checkSwapEncrypted(); err != nil {
		t.Fatalf("encrypted swap: %v", err)
	}
	swapEncrypt = func() (int, error) { return 0, nil }
	if err := checkSwapEncrypted(); !errors.Is(err, errSwapUnencrypted) {
		t.Fatalf("unencrypted swap: %v", err)
	}
	boom := errors.New("boom")
	swapEncrypt = func() (int, error) { return 1, boom }
	if err := checkSwapEncrypted(); !errors.Is(err, boom) {
		t.Fatalf("unreadable: %v", err)
	}
}

// The real sysctl answers without error on a kernel that has it or not.
func TestSwapEncryptReadsTheKernel(t *testing.T) {
	if _, err := swapEncrypt(); err != nil {
		t.Fatalf("sysctl vm.swapencrypt.enable: %v", err)
	}
}
