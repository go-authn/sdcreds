//go:build linux

package s6

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// forwarded are the signals that s6 (and a terminal) send to a service; the
// process that s6 supervises is this one, and the service must see them.
var forwarded = []os.Signal{
	syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGQUIT,
	syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGALRM, syscall.SIGCONT,
}

// maxInheritedFD bounds the descriptors handed to the service.
const maxInheritedFD = 256

type outcome struct {
	code int
	err  error
}

// start forks the service from a thread of its own that has dropped the
// privileges and joined the mount namespace of the caller. The caller keeps
// root and its mounts. Go reports a failed exec through a close-on-exec pipe,
// so a program that cannot run is the error of start, and start returns it
// before the service has run a single instruction. Signals are forwarded and
// the exit status is returned by wait; the child gets SIGKILL if this process
// dies.
func start(u User, argv, env []string) (func() (int, error), error) {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return nil, err
	}
	// The mount namespace is the one of the calling thread (Run unshared it).
	ns, err := os.Open("/proc/thread-self/ns/mnt")
	if err != nil {
		return nil, err
	}
	defer ns.Close()
	wd, _ := os.Getwd()

	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, forwarded...)
	ready, done := make(chan error, 1), make(chan outcome, 1)
	go func() {
		// Never unlocked: this thread takes the identity of the service and ends
		// with the goroutine, so it cannot be reused by anything else. It must
		// also outlive the child (the parent-death signal is tied to it).
		runtime.LockOSThread()
		defer func() { signal.Stop(sigs); close(sigs) }()
		cmd, err := launch(ns, wd, u, path, argv, env)
		ready <- err
		if err != nil {
			return
		}
		go func() {
			for s := range sigs {
				_ = cmd.Process.Signal(s)
			}
		}()
		done <- exitOutcome(cmd.Wait())
	}()
	if err := <-ready; err != nil {
		return nil, err
	}
	return func() (int, error) { o := <-done; return o.code, o.err }, nil
}

// launch runs on the locked thread.
func launch(ns *os.File, wd string, u User, path string, argv, env []string) (*exec.Cmd, error) {
	// Threads share the file-system attributes of the process; setns needs a
	// copy of its own, and then resets the working directory.
	if err := syscall.Unshare(syscall.CLONE_FS); err != nil {
		return nil, fmt.Errorf("unshare: %w", err)
	}
	if err := unix.Setns(int(ns.Fd()), unix.CLONE_NEWNS); err != nil {
		return nil, fmt.Errorf("setns: %w", err)
	}
	if wd != "" {
		if err := syscall.Chdir(wd); err != nil {
			return nil, err
		}
	}
	if err := dropPrivileges(u); err != nil {
		return nil, fmt.Errorf("drop privileges: %w", err)
	}
	cmd := &exec.Cmd{
		Path: path, Args: argv, Env: env,
		Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr,
		ExtraFiles:  inheritedFiles(),
		SysProcAttr: &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
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

func exitOutcome(err error) outcome {
	if err == nil {
		return outcome{}
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return outcome{code: 128 + int(ws.Signal())}
		}
		return outcome{code: ee.ExitCode()}
	}
	return outcome{err: err}
}
