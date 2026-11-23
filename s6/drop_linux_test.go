//go:build linux

package s6

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

const dropHelperEnv = "SDCREDS_S6_DROP_HELPER"

// TestDropHelper is the child of TestPrivilegesAreDroppedForGood: it drops to
// an unprivileged account and reports what it can still do.
func TestDropHelper(t *testing.T) {
	if os.Getenv(dropHelperEnv) == "" {
		t.Skip("child of TestPrivilegesAreDroppedForGood")
	}
	runtime.LockOSThread()
	if err := dropPrivileges(User{UID: 12345, GID: 12345, Groups: []int{12345}}); err != nil {
		t.Fatal(err)
	}
	if syscall.Getuid() != 12345 || syscall.Geteuid() != 12345 {
		t.Fatalf("uid %d/%d", syscall.Getuid(), syscall.Geteuid())
	}
	if rawSetres(trapSetresuid, 0, 0) == nil {
		t.Fatal("root is back")
	}
	if v, err := prctl(39, 0); err != nil || v != 1 { // PR_GET_NO_NEW_PRIVS
		t.Fatalf("no_new_privs: %d %v", v, err)
	}
	if v, err := prctl(prCapbsetRead, 0); err != nil || v != 0 {
		t.Fatalf("CAP_CHOWN still in the bounding set: %d %v", v, err)
	}
	status, err := os.ReadFile("/proc/thread-self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		for _, k := range []string{"CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
			if strings.HasPrefix(line, k) && strings.Trim(strings.TrimPrefix(line, k), "\t 0") != "" {
				t.Errorf("capabilities left: %s", line)
			}
		}
	}
}

func TestPrivilegesAreDroppedForGood(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDropHelper$", "-test.v")
	cmd.Env = append(os.Environ(), dropHelperEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestDropHelper") {
		t.Fatalf("%v\n%s", err, out)
	}
}
