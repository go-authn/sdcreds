package delivery

// VM tests of the split-credential killer (F4): the release never signals a pid
// from a list, and no process of the target can stop or kill the killer.

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
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const (
	testKillerUID  = 32100 // the killer user: owns no process, no password entry
	testUID2       = 32004 // a second target, for two releases at once
	testOtherUID   = 32002 // a user that is not a target: its processes must survive
	testSplitEUID  = 32003 // the effective uid of a process whose real uid is 0
	forkStormLimit = 3000
	// A process whose real, effective and saved uids are three different ones.
	testSplitR = 32201
	testSplitE = 32202
	testSplitS = 32203
)

// The saved-uid offset of struct kinfo_proc is checked against a process that
// KNOWS its saved uid: one whose three ids differ is listed under each of them,
// by the real reading of the process table, and each id is read from its own
// field. A wrong p_svuid offset shows here, which the start check (root: 0/0/0)
// cannot show.
func TestSavedUIDOffsetOfKinfoMatchesAProcessWithThreeIDs(t *testing.T) {
	needRoot(t)
	pid, _ := startHelper(t, nil, "__split3")
	for name, uid := range map[string]int{"real": testSplitR, "effective": testSplitE, "saved": testSplitS} {
		ps, err := listUID(uid)
		if err != nil {
			t.Fatal(err)
		}
		if !containsPid(ps, pid) {
			t.Errorf("the process is not listed under its %s uid %d: %v", name, uid, ps)
		}
	}
	_, err := listKernWith(kernProcAll, 0, func(buf []byte) ([]proc, error) {
		return nil, checkOwnIDs(buf, pid, testSplitR, testSplitE, testSplitS)
	})
	if err != nil {
		t.Fatal(err)
	}
}

// killerHelperMain is the body of the helper processes of these tests.
func killerHelperMain(mode string, args []string) {
	switch mode {
	case "__killerhold":
		// Becomes the killer, shows its credentials, and holds still.
		u, _ := strconv.Atoi(args[0])
		k, _ := strconv.Atoi(args[1])
		g, _ := strconv.Atoi(args[2])
		if err := becomeKiller(u, k, g); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		r, e, s := unix.Getresuid()
		fmt.Println("uids", r, e, s)
		fmt.Println("ready")
		time.Sleep(300 * time.Second)
	case "__probe":
		// As the target: try to stop and to kill the pid.
		pid, _ := strconv.Atoi(args[0])
		fmt.Println(unix.Kill(pid, unix.SIGSTOP), unix.Kill(pid, unix.SIGKILL))
	case "__canary":
		// A process that must survive any release of another user.
		fmt.Println("ready")
		time.Sleep(300 * time.Second)
	case "__split0":
		// Real uid 0, effective uid of somebody: root's own process, not a target.
		if err := unix.Setresuid(0, testSplitEUID, 0); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("ready")
		time.Sleep(300 * time.Second)
	case "__split3":
		// Three different ids: real, effective and saved all differ.
		if err := unix.Setresuid(testSplitR, testSplitE, testSplitS); err != nil {
			fmt.Println("error", err)
			os.Exit(1)
		}
		fmt.Println("ready")
		time.Sleep(300 * time.Second)
	case "__forkstorm":
		for i := 0; i < forkStormLimit; i++ {
			c := exec.Command(os.Args[0], "__sleeper")
			if err := c.Start(); err != nil {
				break
			}
			go func() { _ = c.Wait() }()
			if i == 0 {
				fmt.Println("ready")
			}
		}
		time.Sleep(300 * time.Second)
	}
	os.Exit(0)
}

// startHelper runs a helper mode with a credential (nil: root), waits for its
// "ready", and returns its pid and the lines it printed before.
func startHelper(t *testing.T, cred *syscall.Credential, mode string, args ...string) (int, []string) {
	t.Helper()
	cmd := exec.Command(testExe(), append([]string{mode}, args...)...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Credential: cred}
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
	var lines []string
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if sc.Text() == "ready" {
			return pid, lines
		}
		lines = append(lines, sc.Text())
	}
	t.Fatalf("%s: no ready line: %v", mode, lines)
	return 0, nil
}

func asUser(uid int) *syscall.Credential {
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(uid)}
}

// Tests 1 and 7: the killer holds the credentials (k, u, k), and a process of the
// target can neither stop nor kill it, though it signals everything of its own
// user that it can reach.
func TestTheKillerCannotBeSignalledByTheTarget(t *testing.T) {
	needRoot(t)
	pid, lines := startHelper(t, nil, "__killerhold", itoa(testUID), itoa(testKillerUID), itoa(testKillerUID))
	if want := fmt.Sprintf("uids %d %d %d", testKillerUID, testUID, testKillerUID); len(lines) != 1 || lines[0] != want {
		t.Fatalf("credentials of the killer %v, want %q", lines, want)
	}
	probe := exec.Command(testExe(), "__probe", itoa(pid))
	probe.SysProcAttr = &syscall.SysProcAttr{Credential: asUser(testUID)}
	out, err := probe.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := unix.EPERM.Error() + " " + unix.EPERM.Error()
	if got := strings.TrimSpace(string(out)); got != want {
		t.Fatalf("the target's SIGSTOP and SIGKILL of the killer: %q, want %q", got, want)
	}
	if !alive(pid) {
		t.Fatal("the killer is gone")
	}
}

// Test 2: nothing but the target's processes dies. A root process, a process of
// another user, and a process of real uid 0 with another effective uid are all
// still there, and the killer refuses to take root or the target as its own uid.
func TestReleaseKillsNothingButTheTarget(t *testing.T) {
	base := needRoot(t)
	split, _ := startHelper(t, nil, "__split0")
	plain, _ := startHelper(t, nil, "__canary")
	other, _ := startHelper(t, asUser(testOtherUID), "__canary")
	target := startHostile(t, "kill")
	if err := KillUID(testExe(), testUID, testGID, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the target is gone", func() bool { return !alive(target) })
	for name, pid := range map[string]int{"root": plain, "another user": other, "real uid 0, effective uid set": split} {
		if !alive(pid) {
			t.Errorf("the %s process was killed", name)
		}
	}
	// The identities it refuses.
	old := lookupKiller
	defer func() { lookupKiller = old }()
	for name, k := range map[string]int{"root": 0, "the target": testUID} {
		lookupKiller = func() (int, int, error) { return k, k, nil }
		if err := KillUID(testExe(), testUID, testGID, nil); !errors.Is(err, ErrKiller) {
			t.Errorf("killer %s: %v", name, err)
		}
	}
	// A killer user that owns a process, or that does not exist, is refused at the
	// START: the release could not be trusted, so nothing is delivered.
	cfg := testConfig(t, base, "svc", Credential{"a", []byte("x")})
	lookupKiller = func() (int, int, error) { return testOtherUID, testOtherUID, nil }
	if _, err := Prepare(context.Background(), cfg); !errors.Is(err, ErrKiller) {
		t.Errorf("start with a killer that owns a process: %v", err)
	}
	lookupKiller = func() (int, int, error) { return 0, 0, fmt.Errorf("%w: user absent", ErrKiller) }
	if _, err := Prepare(context.Background(), cfg); !errors.Is(err, ErrKiller) {
		t.Errorf("start with a killer user that was deleted: %v", err)
	}
}

// Test 3: a program that forks as fast as it can is gone at the end, or the
// release says it is not: never a success while a process is left.
func TestReleaseConvergesOnAForkStorm(t *testing.T) {
	needRoot(t)
	startHelper(t, asUser(testUID), "__forkstorm")
	err := KillUID(testExe(), testUID, testGID, nil)
	busy, berr := UIDBusy(testUID)
	if berr != nil {
		t.Fatal(berr)
	}
	switch {
	case err == nil && busy:
		t.Fatal("success reported while the user still has processes")
	case err != nil && !errors.Is(err, ErrUIDSurvives):
		t.Fatal(err)
	case err != nil:
		t.Logf("survivors reported, as allowed: %v", err)
		_ = KillUID(testExe(), testUID, testGID, nil)
	}
}

// Test 4: two releases at the same time, for two users: both end empty.
func TestTwoReleasesAtOnce(t *testing.T) {
	needRoot(t)
	first := startHostile(t, "kill")
	pid2, _ := startHelper(t, asUser(testUID2), "__hostile", "kill")
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, uid := range []int{testUID, testUID2} {
		wg.Add(1)
		go func() { defer wg.Done(); errs[i] = KillUID(testExe(), uid, uid, nil) }()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("release %d: %v", i, err)
		}
	}
	for uid, pid := range map[int]int{testUID: first, testUID2: pid2} {
		eventually(t, "the target is gone", func() bool { return !alive(pid) })
		if busy, err := UIDBusy(uid); err != nil || busy {
			t.Errorf("uid %d is not empty: %v %v", uid, busy, err)
		}
	}
}

// Test 6, and what F5 asks about the killer: a process that holds the user only
// as a set-id program (real uid of another user, effective and saved uid the
// target, PS_SUGID set) is counted by the start check and is NOT reached by the
// killer: cansignal() lets a sender signal a PS_SUGID process only if the
// sender's real or effective uid is the target's REAL uid. It survives the
// release, which says so (ErrUIDSurvives), and the next start is refused.
func TestASetIDHolderOfTheUserSurvivesAndIsReported(t *testing.T) {
	base := needRoot(t)
	dir := filepath.Dir(testExe())
	suid := filepath.Join(dir, "suid")
	self, err := os.ReadFile(testExe())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(suid, self, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(suid) })
	if err := os.Chown(suid, testUID, testGID); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(suid, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(suid, "__sleeper")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: asUser(testOtherUID)}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	go func() { _ = cmd.Wait() }()
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	held := false
	for end := time.Now().Add(3 * time.Second); time.Now().Before(end) && !held; time.Sleep(50 * time.Millisecond) {
		b, err := UIDBusy(testUID)
		held = err == nil && b
	}
	if !held {
		t.Skip("the set-id bit has no effect here (nosuid mount?)")
	}
	if err := KillUID(testExe(), testUID, testGID, nil); !errors.Is(err, ErrUIDSurvives) {
		t.Fatalf("a process the killer cannot reach must be reported: %v", err)
	}
	if !alive(pid) {
		t.Fatal("the set-id process was killed: the analysis of cansignal() is wrong, update the design")
	}
	_, err = Prepare(context.Background(), testConfig(t, base, "svc", Credential{"a", []byte("x")}))
	if !errors.Is(err, ErrUIDBusy) {
		t.Fatalf("the next start: %v, want ErrUIDBusy", err)
	}
}
