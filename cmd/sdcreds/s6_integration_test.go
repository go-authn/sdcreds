//go:build linux

package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/go-authn/sdcreds/s6"
)

// itRig builds the real binary and prepares one credential for the user
// sdcreds-test of the interop container.
type itRig struct {
	t                     *testing.T
	dir, bin, secret, src string
	base                  string
	env                   []string
}

func newITRig(t *testing.T) *itRig {
	t.Helper()
	if os.Getenv("SDCREDS_S6_INTEGRATION") != "1" {
		t.Skip("set SDCREDS_S6_INTEGRATION=1 to run as root with mount privileges")
	}
	if os.Getuid() != 0 {
		t.Fatal("this test must run as root")
	}
	r := &itRig{t: t, dir: t.TempDir()}
	r.bin = filepath.Join(r.dir, "sdcreds")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", r.bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	r.secret = filepath.Join(r.dir, "credential.secret")
	r.env = append(os.Environ(), "SYSTEMD_CREDENTIAL_SECRET="+r.secret)
	if out, err := r.sdcreds("", "setup"); err != nil {
		t.Fatalf("setup: %v: %s", err, out)
	}
	r.src = filepath.Join(r.dir, "src")
	os.MkdirAll(r.src, 0o700)
	if out, err := r.sdcreds("hunter2", "encrypt", "--name=db", "-", filepath.Join(r.src, "db")); err != nil {
		t.Fatalf("encrypt: %v: %s", err, out)
	}
	r.base = "/run/sdcreds-it"
	if err := os.MkdirAll(r.base, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(r.base) })
	return r
}

func (r *itRig) command(stdin string, args ...string) *exec.Cmd {
	cmd := exec.Command(r.bin, args...)
	cmd.Env = r.env
	cmd.Stdin = strings.NewReader(stdin)
	return cmd
}

func (r *itRig) sdcreds(stdin string, args ...string) (string, error) {
	out, err := r.command(stdin, args...).CombinedOutput()
	return string(out), err
}

// runArgs are the arguments of s6-run for the service "web"; s6-run takes the
// key from the file its flag names (root-owned), not from the environment.
func (r *itRig) runArgs(unshare bool, command ...string) []string {
	args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + r.base, "--source=" + r.src, "--secret=" + r.secret}
	if !unshare {
		args = append(args, "--unshare=false")
	}
	return append(args, append([]string{"--"}, command...)...)
}

func (r *itRig) mounted() bool {
	mounts, _ := os.ReadFile("/proc/self/mounts")
	return strings.Contains(string(mounts), filepath.Join(r.base, "web")+" ")
}

func exitCode(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	if err == nil {
		return 0
	}
	return -1
}

// The real s6-run and s6-finish, as root, in the interop container started
// with --privileged: a tmpfs mounted read-only with nosuid, nodev and noexec,
// owned by the service user, whose plaintext goes away with the mount.
// Run it with SDCREDS_S6_INTEGRATION=1; it is skipped otherwise.
func TestS6AsRoot(t *testing.T) {
	r := newITRig(t)
	cwd, _ := os.Getwd()
	script := `d="$CREDENTIALS_DIRECTORY"; echo "pw=$(cat "$d/db")"; echo "uid=$(id -u)"; ` +
		`echo "mount=$(grep " $d " /proc/self/mounts)"; (echo x > "$d/new") 2>/dev/null && echo writable || echo readonly; ` +
		`grep -E '^(NoNewPrivs|CapEff|CapBnd):' /proc/self/status; echo "cwd=$(readlink /proc/self/cwd)"`
	for _, unshare := range []bool{true, false} {
		out, err := r.sdcreds("", r.runArgs(unshare, "/bin/sh", "-c", script)...)
		if err != nil {
			t.Fatalf("unshare=%v: %v: %s", unshare, err, out)
		}
		for _, want := range []string{"pw=hunter2", "uid=1000", "readonly", " tmpfs ", "mount=sdcreds ", "nosuid", "nodev", "noexec",
			"NoNewPrivs:\t1", "CapEff:\t0000000000000000", "CapBnd:\t0000000000000000", "cwd=" + cwd} {
			if !strings.Contains(out, want) {
				t.Errorf("unshare=%v: %q missing from:\n%s", unshare, want, out)
			}
		}
		if !strings.Contains(out, " ro,") && !strings.Contains(out, " ro ") {
			t.Errorf("unshare=%v: not mounted read-only:\n%s", unshare, out)
		}
		// s6-run waits for the service and takes the credentials away itself.
		if r.mounted() {
			t.Errorf("unshare=%v: still mounted after the service ended", unshare)
		}
		if _, err := os.Stat(filepath.Join(r.base, "web")); err == nil {
			t.Errorf("unshare=%v: directory left behind", unshare)
		}
		if !unshare {
			// What a killed run leaves behind (a mount named sdcreds) must not
			// stack under the next run.
			web := filepath.Join(r.base, "web")
			os.MkdirAll(web, 0o700)
			if err := syscall.Mount(s6.MountTag, web, "tmpfs", 0, ""); err != nil {
				t.Fatal(err)
			}
			if out, err := r.sdcreds("", r.runArgs(false, "/bin/true")...); err != nil {
				t.Fatalf("run over a stale mount: %v: %s", err, out)
			}
			if r.mounted() {
				t.Error("the stale mount survived the next run")
			}
		}
		if out, err := r.sdcreds("", "s6-finish", "--service=web", "--base-dir="+r.base); err != nil {
			t.Errorf("finish after the run: %v: %s", err, out)
		}
	}

	// A command that does not exist fails before anything is mounted, even
	// without a private namespace.
	if out, err := r.sdcreds("", r.runArgs(false, "/nonexistent/cmd")...); err == nil {
		t.Errorf("a missing command was run: %s", out)
	}
	if r.mounted() {
		t.Error("credentials left mounted after a failed exec")
	}

	// A command that root may run and the service user may not (it sits in a
	// directory only root can enter) is refused before anything is mounted.
	svc := filepath.Join(r.dir, "service.sh")
	os.WriteFile(svc, []byte("#!/bin/sh\nexit 0\n"), 0o700)
	out, err := r.sdcreds("", r.runArgs(false, svc)...)
	if err == nil {
		t.Errorf("a command the service user cannot execute was run: %s", out)
	}
	if r.mounted() {
		t.Errorf("credentials left mounted after a command the service user cannot execute: %s", out)
	}

	// The environment does not choose the key of s6-run.
	args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + r.base, "--source=" + r.src, "--", "/bin/true"}
	if out, err := r.sdcreds("", args...); err == nil {
		t.Errorf("s6-run used the key that the environment names: %s", out)
	}

	// s6-finish detaches what sdcreds mounted and nothing else.
	foreign := filepath.Join(r.base, "foreign")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("foreign", foreign, "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(foreign, syscall.MNT_DETACH)
	if out, err := r.sdcreds("", "s6-finish", "--service=foreign", "--base-dir="+r.base); err == nil {
		t.Errorf("s6-finish detached a mount that sdcreds did not make: %s", out)
	}
	mounts, _ := os.ReadFile("/proc/self/mounts")
	if !strings.Contains(string(mounts), foreign+" ") {
		t.Error("the foreign mount is gone")
	}
}

// A program that the service user may run as far as the permission bits go, but
// that the kernel will not execute, fails after the privileges are dropped in
// the child, and the parent, which kept them, takes the credentials away: a
// file that is not a program (an ELF header and nothing else), and one on a file
// system mounted noexec.
func TestS6AsRootFailedExecLeavesNothing(t *testing.T) {
	r := newITRig(t)
	bindir, err := os.MkdirTemp("/run", "sdcreds-it-bin")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(bindir)
	os.Chmod(bindir, 0o755)
	badELF := filepath.Join(bindir, "bad-elf")
	if err := os.WriteFile(badELF, append([]byte("\x7fELF\x02\x01\x01"), make([]byte, 64)...), 0o755); err != nil {
		t.Fatal(err)
	}
	noexec := filepath.Join(bindir, "noexec")
	os.Mkdir(noexec, 0o755)
	if err := syscall.Mount("noexec", noexec, "tmpfs", syscall.MS_NOEXEC, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(noexec, syscall.MNT_DETACH)
	truth, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	onNoexec := filepath.Join(noexec, "true")
	if err := os.WriteFile(onNoexec, truth, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, program := range map[string]string{"bad ELF": badELF, "noexec file system": onNoexec} {
		for _, unshare := range []bool{false, true} {
			out, err := r.sdcreds("", r.runArgs(unshare, program)...)
			if err == nil {
				t.Errorf("%s, unshare=%v: ran: %s", name, unshare, out)
			}
			if r.mounted() {
				t.Errorf("%s, unshare=%v: credentials left mounted: %s", name, unshare, out)
			}
			if _, err := os.Stat(filepath.Join(r.base, "web")); err == nil {
				t.Errorf("%s, unshare=%v: directory left behind", name, unshare)
			}
		}
	}
	// The bad ELF gets past the permission check, so it is the status pipe of
	// the child that reports it, not the early refusal.
	out, err := r.sdcreds("", r.runArgs(false, badELF)...)
	if err == nil || !strings.Contains(out, "start "+badELF) {
		t.Errorf("the failed exec is not reported as such: %v: %s", err, out)
	}
}

// s6 supervises s6-run and signals it: the exit status of the service is the
// one of s6-run, a descriptor it was given reaches the service, a signal sent
// to s6-run reaches the service, and the service dies with s6-run.
func TestS6AsRootSupervision(t *testing.T) {
	r := newITRig(t)

	// exit status and an inherited descriptor
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd := r.command("", r.runArgs(true, "/bin/sh", "-c", "echo through >&3; exit 5")...)
	cmd.ExtraFiles = []*os.File{wr}
	err = cmd.Run()
	wr.Close()
	line, _ := bufio.NewReader(rd).ReadString('\n')
	rd.Close()
	if exitCode(err) != 5 || line != "through\n" {
		t.Errorf("exit %d (%v), descriptor said %q", exitCode(err), err, line)
	}
	if r.mounted() {
		t.Error("mounted after the service ended")
	}

	start := func() (*exec.Cmd, int, *bufio.Reader) {
		cmd := r.command("", r.runArgs(false, "/bin/sh", "-c", `trap 'exit 9' TERM; echo $$; echo ready; while :; do sleep 0.1; done`)...)
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(out)
		pidLine, _ := br.ReadString('\n')
		ready, _ := br.ReadString('\n')
		pid, err := strconv.Atoi(strings.TrimSpace(pidLine))
		if err != nil || ready != "ready\n" {
			cmd.Process.Kill()
			t.Fatalf("service did not start: %q %q", pidLine, ready)
		}
		return cmd, pid, br
	}

	// a signal sent to s6-run reaches the service, whose status is returned
	cmd, _, _ = start()
	if !r.mounted() {
		t.Error("not mounted while the service runs")
	}
	cmd.Process.Signal(syscall.SIGTERM)
	if code := exitCode(cmd.Wait()); code != 9 {
		t.Errorf("exit status %d after SIGTERM, want 9", code)
	}
	if r.mounted() {
		t.Error("mounted after the service ended")
	}

	// the service dies with s6-run, which s6-finish then cleans up after
	cmd, pid, _ := start()
	cmd.Process.Kill()
	cmd.Wait()
	dead := false
	for i := 0; i < 50 && !dead; i++ {
		stat, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		dead = err != nil || strings.Contains(string(stat), ") Z")
		if !dead {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if !dead {
		syscall.Kill(pid, syscall.SIGKILL)
		t.Error("the service outlived s6-run")
	}
	if out, err := r.sdcreds("", "s6-finish", "--service=web", "--base-dir="+r.base); err != nil || r.mounted() {
		t.Errorf("finish: %v: %s", err, out)
	}
}
