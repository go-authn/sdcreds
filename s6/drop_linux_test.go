//go:build linux

package s6

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const dropHelperEnv = "SDCREDS_S6_DROP_HELPER"

// TestDropHelper is the child of TestPrivilegesAreDroppedForGood: the launcher
// thread is restricted (no_new_privs, empty bounding set) and keeps its ids.
func TestDropHelper(t *testing.T) {
	if os.Getenv(dropHelperEnv) == "" {
		t.Skip("child of TestPrivilegesAreDroppedForGood")
	}
	runtime.LockOSThread()
	if err := restrictThread(); err != nil {
		t.Fatal(err)
	}
	if v, err := prctl(39, 0); err != nil || v != 1 { // PR_GET_NO_NEW_PRIVS
		t.Fatalf("no_new_privs: %d %v", v, err)
	}
	if v, err := prctl(prCapbsetRead, 0); err != nil || v != 0 {
		t.Fatalf("CAP_CHOWN still in the bounding set: %d %v", v, err)
	}
	if syscall.Getuid() != 0 || syscall.Geteuid() != 0 {
		t.Fatalf("the thread changed its ids: %d/%d", syscall.Getuid(), syscall.Geteuid())
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

// threadUIDs returns the real, effective, saved and file-system uid of every thread
// of this process.
func threadUIDs(t *testing.T) map[string][]string {
	t.Helper()
	dirs, err := filepath.Glob("/proc/self/task/*")
	if err != nil || len(dirs) == 0 {
		t.Fatalf("no threads: %v", err)
	}
	out := map[string][]string{}
	for _, d := range dirs {
		b, err := os.ReadFile(filepath.Join(d, "status"))
		if err != nil {
			continue // the thread ended
		}
		for _, l := range strings.Split(string(b), "\n") {
			if rest, ok := strings.CutPrefix(l, "Uid:"); ok {
				out[filepath.Base(d)] = strings.Fields(rest)
			}
		}
	}
	return out
}

// Only the child takes the identity of the service: while the service runs,
// no thread of this process has any of its ids, so the service cannot act on its
// parent through a thread that shares its uid.
func TestNoThreadOfTheParentTakesTheServiceIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	const svc = 12345
	done := make(chan struct{})
	var wait func() (int, error)
	var serr error
	go func() {
		defer close(done)
		runtime.LockOSThread() // like Run: never unlocked, the thread ends with the goroutine
		wait, serr = start(User{UID: svc, GID: svc, Groups: []int{svc}}, []string{"/bin/sleep", "30"}, os.Environ())
	}()
	<-done
	if serr != nil {
		t.Fatal(serr)
	}
	defer func() {
		_ = syscall.Kill(os.Getpid(), syscall.SIGTERM) // forwarded to the service
		wait()
	}()
	for tid, ids := range threadUIDs(t) {
		for _, id := range ids {
			if id == strconv.Itoa(svc) {
				t.Errorf("thread %s of the parent carries the service uid: %v", tid, ids)
			}
		}
	}
}

func TestJudgeIDs(t *testing.T) {
	u := User{UID: 1000, GID: 2000}
	status := func(uid, gid string) string {
		return "Name:\tx\nUid:\t" + uid + "\nGid:\t" + gid + "\nGroups:\t1\n"
	}
	if err := judgeIDs(status("1000\t1000\t1000\t1000", "2000\t2000\t2000\t2000"), u); err != nil {
		t.Errorf("good ids: %v", err)
	}
	for name, s := range map[string]string{
		"saved uid is root":       status("1000\t1000\t0\t1000", "2000\t2000\t2000\t2000"),
		"real uid is root":        status("0\t1000\t1000\t1000", "2000\t2000\t2000\t2000"),
		"fs uid is root":          status("1000\t1000\t1000\t0", "2000\t2000\t2000\t2000"),
		"effective gid is root":   status("1000\t1000\t1000\t1000", "2000\t0\t2000\t2000"),
		"saved gid is root":       status("1000\t1000\t1000\t1000", "2000\t2000\t0\t2000"),
		"three fields":            status("1000\t1000\t1000", "2000\t2000\t2000\t2000"),
		"not a number":            status("1000\t1000\t1000\tx", "2000\t2000\t2000\t2000"),
		"no Gid line":             "Uid:\t1000\t1000\t1000\t1000\n",
		"no Uid line":             "Gid:\t2000\t2000\t2000\t2000\n",
		"empty":                   "",
		"gid line with uid value": status("1000\t1000\t1000\t1000", "1000\t1000\t1000\t1000"),
		"uid line with gid value": status("2000\t2000\t2000\t2000", "2000\t2000\t2000\t2000"),
	} {
		if err := judgeIDs(s, u); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
