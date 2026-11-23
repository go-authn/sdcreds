//go:build linux

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, out)
	}
	env := append(os.Environ(), "SYSTEMD_CREDENTIAL_SECRET="+filepath.Join(dir, "credential.secret"))
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
		args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src}
		if !unshare {
			args = append(args, "--unshare=false")
		}
		out, err := sdcreds("", append(args, "--", "/bin/sh", "-c", script)...)
		if err != nil {
			t.Fatalf("unshare=%v: %v: %s", unshare, err, out)
		}
		for _, want := range []string{"pw=hunter2", "uid=1000", "readonly", " tmpfs ", "nosuid", "nodev", "noexec"} {
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
	args := []string{"s6-run", "--service=web", "--user=sdcreds-test", "--base-dir=" + base, "--source=" + src, "--unshare=false", "--", "/nonexistent/cmd"}
	if out, err := sdcreds("", args...); err == nil {
		t.Errorf("a missing command was run: %s", out)
	}
	mounts, _ := os.ReadFile("/proc/self/mounts")
	if strings.Contains(string(mounts), filepath.Join(base, "web")) {
		t.Error("credentials left mounted after a failed exec")
	}
}
