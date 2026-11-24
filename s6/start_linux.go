//go:build linux

package s6

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// maxInheritedFD bounds the descriptors handed to the service.
const maxInheritedFD = 256

type outcome struct {
	code int
	err  error
}

// Seams for the tests: none of these calls can be made to fail on a real system.
var (
	openRoot = func() (*os.File, error) {
		return os.OpenFile("/", os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	}
	openNS     = func() (*os.File, error) { return os.Open("/proc/thread-self/ns/mnt") }
	restrict   = restrictThread
	chroot     = syscall.Chroot
	judgeChild = judgeIDs
)

// start forks the service from a thread of its own that has dropped the
// privileges and joined the mount namespace of the caller. The caller keeps
// root and its mounts. Go reports a failed exec through a close-on-exec pipe,
// so a program that cannot run is the error of start, and start returns it
// before the service has run a single instruction. Signals are forwarded and
// the exit status is returned by wait; the child gets SIGKILL if this process
// dies.
func start(u User, argv, env []string) (func() (int, error), error) {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, forwarded...)
	return startWith(sigs, func() { signal.Stop(sigs) }, u, argv, env)
}

// startWith is start with the signals to forward given: every signal read from
// sigs is delivered to the service exactly once, whether it arrived before or
// after the service was forked, because sigs has one reader. stop is called once
// the service has ended or failed to start.
func startWith(sigs <-chan os.Signal, stop func(), u User, argv, env []string) (func() (int, error), error) {
	fin := make(chan struct{})
	started := false
	defer func() {
		if !started {
			stop()
			close(fin)
		}
	}()
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}
	// The mount namespace is the one of the calling thread (Run unshared it).
	ns, err := openNS()
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	// The root of this thread, which setns resets in the launcher: opened here,
	// in the namespace the launcher will join.
	root, err := openRoot()
	if err != nil {
		return nil, fmt.Errorf("cannot save the root directory: %w", err)
	}
	defer root.Close()
	wd, _ := os.Getwd()

	ready, done := make(chan error, 1), make(chan outcome, 1)
	started = true
	go func() {
		// Never unlocked: this thread takes the identity of the service and ends
		// with the goroutine, so it cannot be reused by anything else. It must
		// also outlive the child (the parent-death signal is tied to it).
		runtime.LockOSThread()
		defer func() { stop(); close(fin) }()
		cmd, err := launch(ns, root, wd, u, path, argv, env)
		ready <- err
		if err != nil {
			return
		}
		go func() {
			for {
				select {
				case s := <-sigs:
					_ = cmd.Process.Signal(s)
				case <-fin:
					return
				}
			}
		}()
		done <- exitOutcome(cmd.Wait())
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return func() (int, error) { o := <-done; return o.code, o.err }, nil
}

// launch runs on the locked thread. Only the child ever takes the identity of
// the service: this thread, and the process it belongs to, stay root, so the
// service has no thread of its parent that carries its own ids.
func launch(ns, root *os.File, wd string, u User, path string, argv, env []string) (*exec.Cmd, error) {
	// Threads share the file-system attributes of the process; setns needs a
	// copy of its own, and then resets the root and the working directory.
	// A failure is reported by setns, which refuses a thread that shares them.
	_ = syscall.Unshare(syscall.CLONE_FS)
	if err := enterNamespace(ns, root, wd); err != nil {
		return nil, err
	}
	if err := restrict(u.Keep); err != nil {
		return nil, fmt.Errorf("restrict: %w", err)
	}
	groups := make([]uint32, 0, len(u.Groups)+1)
	for _, g := range u.Groups {
		groups = append(groups, uint32(g))
	}
	if len(groups) == 0 {
		groups = append(groups, uint32(u.GID))
	}
	cmd := &exec.Cmd{
		Path: path, Args: argv, Env: env,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		ExtraFiles: inheritedFiles(),
		SysProcAttr: &syscall.SysProcAttr{
			Pdeathsig: syscall.SIGKILL,
			// Set in the child, between fork and exec.
			Credential: &syscall.Credential{Uid: uint32(u.UID), Gid: uint32(u.GID), Groups: groups},
		},
	}
	// The kept capabilities become ambient in the child, after its setuid (see
	// restrictThread); with none, the field stays empty and the child is v0.1.0's.
	for _, c := range u.Keep {
		cmd.SysProcAttr.AmbientCaps = append(cmd.SysProcAttr.AmbientCaps, uintptr(c))
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	// Whatever the kernel said, the child must have nothing of root left.
	status, err := os.ReadFile("/proc/" + strconv.Itoa(cmd.Process.Pid) + "/status")
	if err == nil {
		err = judgeChild(string(status), u)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("the service did not take the identity of %d:%d: %w", u.UID, u.GID, err)
	}
	return cmd, nil
}

// judgeIDs reads the real, effective, saved and file-system ids of a
// /proc/<pid>/status and refuses any that is not the user's.
func judgeIDs(status string, u User) error {
	seen := map[string]bool{}
	for _, line := range strings.Split(status, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		want := u.UID
		switch key {
		case "Uid":
		case "Gid":
			want = u.GID
		default:
			continue
		}
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 4 {
			return fmt.Errorf("%s line has %d fields", key, len(f))
		}
		for _, v := range f {
			if n, err := strconv.Atoi(v); err != nil || n != want {
				return fmt.Errorf("%s is %s, not %d", key, strings.Join(f, " "), want)
			}
		}
		seen[key] = true
	}
	if !seen["Uid"] || !seen["Gid"] {
		return errors.New("no Uid or Gid line")
	}
	return nil
}

// enterNamespace moves this thread into the mount namespace of ns and puts back
// what setns resets: the root directory (a service started from a chroot runs
// in that chroot, not in the tree of the host) and the working directory. The
// thread must have its own file-system attributes. A root that cannot be put
// back is an error: nothing is started from a tree it was not meant for.
func enterNamespace(ns, root *os.File, wd string) error {
	if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("setns: %w", err)
	}
	if err := syscall.Fchdir(int(root.Fd())); err != nil {
		return fmt.Errorf("could not restore the root directory: %w", err)
	}
	if err := chroot("."); err != nil {
		return fmt.Errorf("could not restore the root directory: %w", err)
	}
	if wd != "" {
		if err := syscall.Chdir(wd); err != nil {
			return err
		}
	}
	return nil
}

// inheritedFiles are the descriptors above 2 that this process was given to
// pass on (the ones without close-on-exec, such as a notification pipe of s6);
// Go opens every descriptor of its own close-on-exec.
func inheritedFiles() []*os.File {
	var files []*os.File
	last := 0
	for fd := 3; fd < maxInheritedFD; fd++ {
		fl, _, e := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0)
		if e != 0 || fl&syscall.FD_CLOEXEC != 0 {
			files = append(files, nil)
			continue
		}
		files = append(files, os.NewFile(uintptr(fd), ""))
		last = fd - 2
	}
	return files[:last]
}

// exitOutcome turns the result of Wait into an outcome; no error is status 0.
func exitOutcome(err error) outcome {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return outcome{code: 128 + int(ws.Signal())}
		}
		return outcome{code: ee.ExitCode()}
	}
	return outcome{err: err}
}
