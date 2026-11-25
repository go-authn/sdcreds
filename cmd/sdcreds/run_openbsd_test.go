//go:build openbsd

package main

// These tests drive the real `sdcreds` binary (SDCREDS_BIN, installed where an
// unprivileged user can execute it) as root, on an OpenBSD machine: a real mount,
// the daemon's exit, SIGKILL of sdcreds, a leftover swept at start, and the
// refusals that must happen before a key is read. They skip elsewhere.

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
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

// The default machine id is `sysctl hw.uuid`.
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
