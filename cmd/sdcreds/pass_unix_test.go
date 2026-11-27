//go:build unix

package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// F2: nothing is passed unless asked for; the defaults of stubEnv are unchanged.
func TestStubEnvPassesNothingByDefault(t *testing.T) {
	env := []string{"NOTIFY_SOCKET=/run/n", "LISTEN_FDS=1", "LISTEN_PID=7", "LANG=C"}
	got := strings.Join(stubEnv(env, "/c"), ",")
	if got != "PATH="+defaultPath+",CREDENTIALS_DIRECTORY=/c,LANG=C" {
		t.Errorf("default env: %s", got)
	}
}

// F2: --pass-env names are handed on, as they are; one that is unset is not
// invented; the names sdcreds owns cannot be taken from the caller whatever the
// list says.
func TestStubEnvPassEnv(t *testing.T) {
	env := []string{"NOTIFY_SOCKET=/run/n", "LISTEN_FDS=1", "OTHER=x", "PATH=/evil", "CREDENTIALS_DIRECTORY=/old", "__SDCREDS_PASSFD=9"}
	got := strings.Join(stubEnv(env, "/c", "NOTIFY_SOCKET", "LISTEN_FDS", "LISTEN_PID", "PATH", "CREDENTIALS_DIRECTORY", "__SDCREDS_PASSFD"), ",")
	if got != "PATH="+defaultPath+",CREDENTIALS_DIRECTORY=/c,NOTIFY_SOCKET=/run/n,LISTEN_FDS=1" {
		t.Errorf("pass env: %s", got)
	}
}

func TestCheckPassEnvRefusals(t *testing.T) {
	if err := checkPassEnv([]string{"NOTIFY_SOCKET", "LISTEN_FDS", "LISTEN_PID", "_X1"}); err != nil {
		t.Errorf("valid names: %v", err)
	}
	for name, want := range map[string]error{
		"PATH": errPassEnvOwned, "CREDENTIALS_DIRECTORY": errPassEnvOwned, "__SDCREDS_RLIMITS": errPassEnvOwned,
		"__SDCREDS_PASSFD": errPassEnvOwned, "A=B": errPassEnvName, "": errPassEnvName, "1X": errPassEnvName, "A B": errPassEnvName,
	} {
		if err := checkPassEnv([]string{"NOTIFY_SOCKET", name}); !errors.Is(err, want) {
			t.Errorf("%q: %v, want %v", name, err, want)
		}
	}
}

func TestCheckPassFDsRefusals(t *testing.T) {
	old := fdFlags
	t.Cleanup(func() { fdFlags = old })
	fdFlags = func(fd int) (int, error) {
		switch fd {
		case 6:
			return unix.FD_CLOEXEC, nil
		case 5, 8:
			return 0, nil
		}
		return 0, unix.EBADF
	}
	if err := checkPassFDs([]int{5, 8}); err != nil {
		t.Errorf("valid: %v", err)
	}
	if err := checkPassFDs(nil); err != nil {
		t.Errorf("none: %v", err)
	}
	for fd, want := range map[int]error{
		0: errPassFDOwned, 1: errPassFDOwned, 2: errPassFDOwned, 3: errPassFDOwned,
		-1: errPassFDRange, maxPassFD + 1: errPassFDRange,
		7: errPassFDClosed, 6: errPassFDOwn,
	} {
		if err := checkPassFDs([]int{5, fd}); !errors.Is(err, want) {
			t.Errorf("fd %d: %v, want %v", fd, err, want)
		}
	}
}

func TestParsePassFDs(t *testing.T) {
	if got, err := parsePassFDs([]string{"A=1"}); err != nil || got != nil {
		t.Errorf("absent: %v %v", got, err)
	}
	if got, err := parsePassFDs([]string{passFDEnv + "=4,9"}); err != nil || len(got) != 2 || got[0] != 4 || got[1] != 9 {
		t.Errorf("4,9: %v %v", got, err)
	}
	for _, bad := range []string{"", "3", "x", "4,", "5000"} {
		if _, err := parsePassFDs([]string{passFDEnv + "=" + bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// With nothing to pass, stubFiles hands over the gate only and adds no variable.
func TestStubFilesWithoutPassFDs(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	env := []string{"A=1"}
	files := stubFiles(r, nil, &env)
	if len(files) != 1 || files[0] != r || len(env) != 1 {
		t.Errorf("files %v env %v", files, env)
	}
}

// A malformed descriptor list reaching the stub stops it before the program
// runs; a valid one keeps those descriptors (closeExcept), not closeFrom(3).
func TestExecGateDescriptorList(t *testing.T) {
	oldExec, oldGate, oldFrom, oldExcept, oldUmask, oldLimits := execProgram, gateFile, closeFrom, closeExcept, umask, limitsApply
	t.Cleanup(func() {
		execProgram, gateFile, closeFrom, closeExcept, umask, limitsApply = oldExec, oldGate, oldFrom, oldExcept, oldUmask, oldLimits
	})
	umask = func(int) {}
	limitsApply = func([]classRlimit) error { return nil }
	from, except, execed := 0, []int(nil), false
	closeFrom = func(n int) { from = n }
	closeExcept = func(n int, keep []int) { except = keep }
	execProgram = func(string, []string, []string) error { execed = true; return errors.New("seam") }
	feed := func() {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		gateFile = func() *os.File { return r }
		w.Write([]byte{goByte})
		w.Close()
	}
	t.Setenv(passFDEnv, "x")
	feed()
	if err := execGate([]string{"--", "/bin/p"}); err == nil || execed || from != 0 || except != nil {
		t.Errorf("bad list: err=%v execed=%v", err, execed)
	}
	t.Setenv(passFDEnv, "5,9")
	feed()
	if err := execGate([]string{"--", "/bin/p"}); err == nil || !execed || from != 0 || len(except) != 2 {
		t.Errorf("good list: err=%v execed=%v from=%d except=%v", err, execed, from, except)
	}
}

// F7: a failure of the stub (no program) ends main with exitFailed, not with the
// 1 a daemon may return.
func TestStubFailureExitsWithTheReservedStatus(t *testing.T) {
	defer func(o func(int), a []string) { osExit, os.Args = o, a }(osExit, os.Args)
	code := -1
	osExit = func(c int) { code = c }
	os.Args = []string{"sdcreds", stubCommand, "--"}
	main()
	if code != exitFailed {
		t.Errorf("stub failure: exit %d", code)
	}
}

// stubHelperEnv makes this test binary act as the exec stub.
const stubHelperEnv = "SDCREDS_TEST_STUB_SCRIPT"

// TestStubHelperProcess is not a test: it is the child of
// TestPassThroughReachesTheProgram, which runs the real stub in it.
func TestStubHelperProcess(t *testing.T) {
	script := os.Getenv(stubHelperEnv)
	if script == "" {
		t.Skip("helper process")
	}
	os.Unsetenv(stubHelperEnv)
	err := execGate([]string{"--", "/bin/sh", "-c", script})
	t.Fatal(err) // execGate returns only on failure
}

// F2: NOTIFY_SOCKET and LISTEN_* work through the opt-in: the variables arrive,
// the passed descriptor is open at the same number in the program, and a
// descriptor that was not named is closed.
func TestPassThroughReachesTheProgram(t *testing.T) {
	passR, passW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer passR.Close()
	leakR, leakW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer leakR.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// What a supervisor hands sdcreds: an inherited descriptor, not close-on-exec.
	// F_DUPFD makes a copy that is not close-on-exec, at a number from 100: low
	// enough to be under the child's descriptor limit whatever else is open.
	fd, err := unix.FcntlInt(passW.Fd(), unix.F_DUPFD, 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPassFDs([]int{fd}); err != nil {
		t.Fatalf("an inherited descriptor is refused: %v", err)
	}
	leakFD, err := unix.FcntlInt(leakW.Fd(), unix.F_DUPFD, 100)
	if err != nil {
		t.Fatal(err)
	}
	script := `echo "$NOTIFY_SOCKET $LISTEN_FDS $LISTEN_PID ${HOME-unset} ${__SDCREDS_PASSFD-gone}"; echo passed >&` +
		strconv.Itoa(fd) + `; echo leaked >&` + strconv.Itoa(leakFD) + ` 2>/dev/null && echo LEAK; true`
	c := exec.Command(os.Args[0], "-test.run=^TestStubHelperProcess$")
	c.Env = append(stubEnv([]string{"NOTIFY_SOCKET=/run/n.sock", "LISTEN_FDS=1", "LISTEN_PID=42", "HOME=/root"}, "/creds", "NOTIFY_SOCKET", "LISTEN_FDS", "LISTEN_PID"), stubHelperEnv+"="+script)
	files := stubFiles(gateR, []int{fd}, &c.Env)
	// A descriptor that leaked into the stub and was not named.
	for len(files) <= leakFD-3 {
		files = append(files, nil)
	}
	files[leakFD-3] = os.NewFile(uintptr(leakFD), "leak")
	c.ExtraFiles = files
	var out strings.Builder
	c.Stdout = &out
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	// The child holds its own copies now: close the parent's, so that the
	// reading end sees EOF.
	for _, f := range c.ExtraFiles {
		if f != nil {
			f.Close()
		}
	}
	gateW.Write([]byte{goByte})
	gateW.Close()
	passW.Close() // the program holds the only other write end
	leakW.Close()
	if err := c.Wait(); err != nil {
		t.Fatalf("stub: %v\n%s", err, out.String())
	}
	if got := strings.TrimSpace(out.String()); got != "/run/n.sock 1 42 unset gone" {
		t.Errorf("program output %q", got)
	}
	b, _ := io.ReadAll(passR)
	if strings.TrimSpace(string(b)) != "passed" {
		t.Errorf("the passed descriptor %d did not reach the program: %q", fd, b)
	}
	if strings.Contains(out.String(), "LEAK") {
		t.Errorf("a descriptor that was not named reached the program")
	}
}
