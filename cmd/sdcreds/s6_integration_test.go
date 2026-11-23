//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// The real s6-run and s6-finish, as root, in the interop container started
// with --privileged: a tmpfs mounted read-only with nosuid, nodev and noexec,
// owned by the service user, whose plaintext goes away with the mount.
// Run it with SDCREDS_S6_INTEGRATION=1; it is skipped otherwise.
func TestS6AsRoot(t *testing.T) {
	if os.Getenv("SDCREDS_S6_INTEGRATION") != "1" {
		t.Skip("set SDCREDS_S6_INTEGRATION=1 to run as root with mount privileges")
	}
	if os.Getuid() != 0 {
		t.Fatal("this test must run as root")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "sdcreds")
	if out, err := exec.Command("go", "build", "-buildvcs=false", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	secret := filepath.Join(dir, "credential.secret")
	env := append(os.Environ(), "SYSTEMD_CREDENTIAL_SECRET="+secret)
	sdcreds := func(stdin string, args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Env = env
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := sdcreds("", "setup"); err != nil {
		t.Fatalf("setup: %v: %s", err, out)
	}
	src := filepath.Join(dir, "src")
	os.MkdirAll(src, 0o700)
	if out, err := sdcreds("hunter2", "encrypt", "--name=db", "-", filepath.Join(src, "db")); err != nil {
		t.Fatalf("encrypt: %v: %s", err, out)
	}
	base := "/run/sdcreds-it"
	if err := os.MkdirAll(base, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(base)

	script := `d="$CREDENTIALS_DIRECTORY"; echo "pw=$(cat "$d/db")"; echo "uid=$(id -u)"; ` +
		`echo "mount=$(grep " $d " /proc/self/mounts)"; (echo x > "$d/new") 2>/dev/null && echo writable || echo readonly`
	for _, unshare := range []bool{true, false} {
		// s6-run takes the key from the files its flags name (root-owned), not
		// from the environment, which also names this secret here.
		args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src, "--secret=" + secret}
		if !unshare {
			args = append(args, "--unshare=false")
		}
		out, err := sdcreds("", append(args, "--", "/bin/sh", "-c", script)...)
		if err != nil {
			t.Fatalf("unshare=%v: %v: %s", unshare, err, out)
		}
		for _, want := range []string{"pw=hunter2", "uid=1000", "readonly", " tmpfs ", "mount=sdcreds ", "nosuid", "nodev", "noexec"} {
			if !strings.Contains(out, want) {
				t.Errorf("unshare=%v: %q missing from:\n%s", unshare, want, out)
			}
		}
		if !strings.Contains(out, " ro,") && !strings.Contains(out, " ro ") {
			t.Errorf("unshare=%v: not mounted read-only:\n%s", unshare, out)
		}
		mounts, _ := os.ReadFile("/proc/self/mounts")
		mounted := strings.Contains(string(mounts), filepath.Join(base, "web"))
		if mounted == unshare {
			t.Errorf("unshare=%v: mounted in the host namespace: %v", unshare, mounted)
		}
		if !unshare {
			// A second run without a finish must not stack a mount on the
			// first, and one finish must leave nothing mounted.
			if out, err := sdcreds("", append(args, "--", "/bin/true")...); err != nil {
				t.Fatalf("second run: %v: %s", err, out)
			}
			mounts, _ = os.ReadFile("/proc/self/mounts")
			if n := strings.Count(string(mounts), filepath.Join(base, "web")+" "); n != 1 {
				t.Errorf("%d mounts of the service directory after two runs", n)
			}
		}
		if out, err := sdcreds("", "s6-finish", "--service=web", "--base-dir="+base); err != nil {
			t.Fatalf("finish: %v: %s", err, out)
		}
		if _, err := os.Stat(filepath.Join(base, "web")); err == nil {
			t.Errorf("unshare=%v: directory left behind", unshare)
		}
		mounts, _ = os.ReadFile("/proc/self/mounts")
		if strings.Contains(string(mounts), filepath.Join(base, "web")) {
			t.Errorf("unshare=%v: still mounted after finish", unshare)
		}
		if out, err := sdcreds("", "s6-finish", "--service=web", "--base-dir="+base); err != nil {
			t.Errorf("finish is not idempotent: %v: %s", err, out)
		}
	}
	// A command that does not exist fails before anything is mounted, even
	// without a private namespace.
	args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src, "--secret=" + secret, "--unshare=false", "--", "/nonexistent/cmd"}
	if out, err := sdcreds("", args...); err == nil {
		t.Errorf("a missing command was run: %s", out)
	}
	mounts, _ := os.ReadFile("/proc/self/mounts")
	if strings.Contains(string(mounts), filepath.Join(base, "web")) {
		t.Error("credentials left mounted after a failed exec")
	}

	// A command that root may run and the service user may not (it sits in a
	// directory only root can enter) is refused before anything is mounted.
	svc := filepath.Join(dir, "service.sh")
	os.WriteFile(svc, []byte("#!/bin/sh\nexit 0\n"), 0o700)
	args = []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src, "--secret=" + secret, "--unshare=false", "--", svc}
	out, err := sdcreds("", args...)
	if err == nil {
		t.Errorf("a command the service user cannot execute was run: %s", out)
	}
	mounts, _ = os.ReadFile("/proc/self/mounts")
	if strings.Contains(string(mounts), filepath.Join(base, "web")) {
		t.Errorf("credentials left mounted after a command the service user cannot execute: %s", out)
	}

	// The environment does not choose the key of s6-run.
	args = []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src, "--", "/bin/true"}
	if out, err := sdcreds("", args...); err == nil {
		t.Errorf("s6-run used the key that the environment names: %s", out)
	}

	// s6-finish detaches what sdcreds mounted and nothing else.
	foreign := filepath.Join(base, "foreign")
	if err := os.MkdirAll(foreign, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mount("foreign", foreign, "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	defer syscall.Unmount(foreign, syscall.MNT_DETACH)
	if out, err := sdcreds("", "s6-finish", "--service=foreign", "--base-dir="+base); err == nil {
		t.Errorf("s6-finish detached a mount that sdcreds did not make: %s", out)
	}
	mounts, _ = os.ReadFile("/proc/self/mounts")
	if !strings.Contains(string(mounts), foreign+" ") {
		t.Error("the foreign mount is gone")
	}
}
