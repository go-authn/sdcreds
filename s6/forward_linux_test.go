//go:build linux

package s6

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// These tests hold the Linux half of one property: once the service has been
// reaped, a signal forwarded by root never reaches that pid, which the kernel
// may give to another process. They go through startWith, the real forwarder,
// and observe the delivery through sendSignal. They need root (the service is
// launched with dropped ids) and skip otherwise; the privileged CI lane runs them.

const noPidfdEnv = "SDCREDS_TEST_NO_PIDFD"

// With SDCREDS_TEST_NO_PIDFD=1 this binary refuses pidfd_open with ENOSYS from
// its first instruction, as a kernel older than 5.3 or a seccomp profile does,
// so Go falls back to the pid with a done flag. The filter is installed on all
// threads (TSYNC) before the runtime decides, and the service inherits it.
func init() {
	if os.Getenv(noPidfdEnv) != "1" {
		return
	}
	// pidfd_open has the same number on every architecture that has it, so the
	// filter needs no architecture check.
	prog := []syscall.SockFilter{
		{Code: 0x20, K: 0}, // ld nr
		{Code: 0x15, Jt: 0, Jf: 1, K: unix.SYS_PIDFD_OPEN},   // pidfd_open?
		{Code: 0x06, K: 0x00050000 | uint32(syscall.ENOSYS)}, // yes: ERRNO(ENOSYS)
		{Code: 0x06, K: 0x7fff0000},                          // no: allow
	}
	fp := syscall.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	if _, _, e := syscall.RawSyscall6(syscall.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); e != 0 {
		panic("no_new_privs: " + e.Error())
	}
	const setModeFilter, tsync = 1, 1
	if r, _, e := syscall.RawSyscall(unix.SYS_SECCOMP, setModeFilter, tsync, uintptr(unsafe.Pointer(&fp))); r != 0 || e != 0 {
		panic(fmt.Sprintf("seccomp: %d %v", r, e))
	}
}

// pidfdOff reports whether this process cannot open a pidfd.
func pidfdOff() bool {
	_, _, e := syscall.Syscall(unix.SYS_PIDFD_OPEN, uintptr(os.Getpid()), 0, 0)
	return e == syscall.ENOSYS
}

// observe replaces sendSignal for the test: hook runs in place of the delivery
// and may call orig, the real one.
func observe(t *testing.T, hook func(orig func(*os.Process, os.Signal) error, p *os.Process, s os.Signal) error) {
	t.Helper()
	orig := sendSignal
	sendSignal = func(p *os.Process, s os.Signal) error { return hook(orig, p, s) }
	t.Cleanup(func() { sendSignal = orig })
}

func launchStub(t *testing.T, sigs <-chan os.Signal, argv ...string) func() (int, error) {
	t.Helper()
	w, err := startWith(sigs, func() {}, User{UID: 12345, GID: 12345}, argv, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func inChild(t *testing.T) bool { return os.Getenv(noPidfdEnv) == "1" }

// The forwarder holds a signal while the service is killed and reaped, then
// delivers it: the delivery is refused with os.ErrProcessDone. When the kernel
// lets another process have the pid at that moment (ns_last_pid), that process
// is untouched.
func TestForwardedSignalAfterTheReapIsRefused(t *testing.T) {
	needRoot(t)
	if inChild(t) && !pidfdOff() {
		t.Fatal("the pidfd refusal is not in force")
	}
	t.Logf("pidfd off: %v", pidfdOff())
	entered, gate, result := make(chan int, 1), make(chan struct{}), make(chan error, 1)
	observe(t, func(orig func(*os.Process, os.Signal) error, p *os.Process, s os.Signal) error {
		entered <- p.Pid
		<-gate
		err := orig(p, s)
		result <- err
		return err
	})
	sigs := make(chan os.Signal, 1)
	wait := launchStub(t, sigs, "/bin/sleep", "30")
	sigs <- syscall.SIGWINCH
	var pid int
	select {
	case pid = <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the signal was not forwarded while the service ran")
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	if code, _ := wait(); code != 128+int(syscall.SIGKILL) {
		t.Fatalf("status %d", code)
	}
	// The service is reaped; the forwarder has not delivered yet.
	victim, died := reusePid(t, pid)
	close(gate)
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrProcessDone) {
			t.Errorf("a signal forwarded after the reap was not refused: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the forwarder did not return")
	}
	if victim != nil {
		select {
		case <-died:
			t.Errorf("the process that took pid %d was signalled", pid)
		case <-time.After(300 * time.Millisecond):
		}
		_ = victim.Process.Kill()
		<-died
	}
}

// reusePid makes the next fork of this pid namespace return pid, as a busy
// system eventually does, and starts a sleeper that must get it. It returns nil
// when the namespace does not let this process choose (no ns_last_pid, or a race).
func reusePid(t *testing.T, pid int) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	for try := 0; try < 20; try++ {
		if err := os.WriteFile("/proc/sys/kernel/ns_last_pid", []byte(strconv.Itoa(pid-1)), 0o644); err != nil {
			t.Logf("pid reuse not forced: %v", err)
			return nil, nil
		}
		c := exec.Command("/bin/sleep", "30")
		if err := c.Start(); err != nil {
			t.Fatal(err)
		}
		if c.Process.Pid == pid {
			died := make(chan struct{})
			go func() { _ = c.Wait(); close(died) }()
			t.Logf("pid %d is now another process", pid)
			return c, died
		}
		_ = c.Process.Kill()
		_ = c.Wait()
	}
	t.Log("pid reuse not forced: the pid was taken every time")
	return nil, nil
}

// Signals are forwarded in a loop while a service exits and is reaped, many
// times. Every delivery that begins after the reap is refused; none is accepted.
// The delay before the delivery makes deliveries straddle the reap.
func TestForwarderNeverSignalsAfterTheReapStress(t *testing.T) {
	needRoot(t)
	if inChild(t) && !pidfdOff() {
		t.Fatal("the pidfd refusal is not in force")
	}
	iterations := 300
	if testing.Short() {
		iterations = 50
	}
	var reaped atomic.Bool
	var late, accepted, notRefused atomic.Int64
	observe(t, func(orig func(*os.Process, os.Signal) error, p *os.Process, s os.Signal) error {
		time.Sleep(100 * time.Microsecond)
		after := reaped.Load()
		err := orig(p, s)
		if after {
			late.Add(1)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, os.ErrProcessDone) {
				notRefused.Add(1)
			}
		}
		return err
	})
	for i := 0; i < iterations; i++ {
		reaped.Store(false)
		sigs := make(chan os.Signal, 16)
		for range 8 {
			sigs <- syscall.SIGWINCH
		}
		wait := launchStub(t, sigs, "/bin/true")
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				case sigs <- syscall.SIGWINCH:
				default:
				}
			}
		}()
		wait()
		reaped.Store(true)
		time.Sleep(2 * time.Millisecond)
		close(stop)
	}
	t.Logf("%d deliveries began after the reap; %d accepted, %d refused in another way", late.Load(), accepted.Load(), notRefused.Load())
	if accepted.Load() != 0 || notRefused.Load() != 0 {
		t.Errorf("%d signals were sent after the reap (%d refused another way)", accepted.Load(), notRefused.Load())
	}
	if late.Load() == 0 {
		t.Error("the stress never reached the window after the reap: it proves nothing")
	}
}

// Without pidfd the done flag does the same job: this binary is run again with
// pidfd_open refused, and both tests above must pass there.
func TestForwarderWithoutPidfd(t *testing.T) {
	needRoot(t)
	if inChild(t) {
		t.Skip("this is the child")
	}
	env := append(os.Environ(), noPidfdEnv+"=1")
	out, err := helperOutput(t, env, "-test.run=^(TestForwardedSignalAfterTheReapIsRefused|TestForwarderNeverSignalsAfterTheReapStress)$", "-test.v")
	s := string(out)
	for _, want := range []string{"--- PASS: TestForwardedSignalAfterTheReapIsRefused", "--- PASS: TestForwarderNeverSignalsAfterTheReapStress", "pidfd off: true"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q (%v)\n%s", want, err, s)
		}
	}
}
