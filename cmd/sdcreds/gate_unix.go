//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds/delivery"
)

const (
	// stubCommand is the hidden command `run` re-executes as the target user.
	// It waits on descriptor 3 for goByte and only then execs the program:
	// nothing the target runs exists before the helper guards its process group.
	stubCommand = "__sdcreds-exec"
	goByte      = 'g'
)

// Seams for the tests.
var (
	execProgram = syscall.Exec
	gateFile    = func() *os.File { return os.NewFile(3, "gate") }
)

// envWithout copies env without the variable name.
func envWithout(env []string, name string) []string {
	out := make([]string, 0, len(env)+1)
	for _, e := range env {
		if !strings.HasPrefix(e, name+"=") {
			out = append(out, e)
		}
	}
	return out
}

var errGateClosed = errors.New("the owner went away before releasing the program")

// execGate is the stub: args is "--", PROGRAM, ARG... It reads one byte from
// the gate. goByte execs the program with this process's environment; anything
// else, EOF included (the owner died first), exits without running it.
func execGate(args []string) error {
	if len(args) < 2 || args[0] != "--" {
		return errors.New("usage: " + stubCommand + " -- PROGRAM [ARG...]")
	}
	g := gateFile()
	var b [1]byte
	n, err := g.Read(b[:])
	g.Close() // the program must not inherit the gate
	if n != 1 || b[0] != goByte {
		if err == nil {
			err = errors.New("unexpected byte")
		}
		return fmt.Errorf("%w: %v", errGateClosed, err)
	}
	// The program starts with nothing the stub held: no descriptor above stderr
	// (the helper's pipes, the lock) and a private umask.
	// --pass-fd descriptors are the one thing it keeps, named by passFDEnv.
	env := os.Environ()
	keep, err := parsePassFDs(env)
	if err != nil {
		return err
	}
	if len(keep) == 0 {
		closeFrom(3)
	} else {
		closeExcept(3, keep)
	}
	umask(0o077)
	// The limits of the login class, if --class asked for them: a limit that
	// cannot be applied means the program does not run.
	spec := ""
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, rlimitEnv+"="); ok {
			spec = v
		}
	}
	env = envWithout(envWithout(env, rlimitEnv), passFDEnv)
	ls, err := DecodeLimits(spec)
	if err == nil {
		err = limitsApply(ls)
	}
	if err != nil {
		return fmt.Errorf("login class limits: %w", err)
	}
	prog := args[1]
	return fmt.Errorf("exec %s: %w", prog, execProgram(prog, args[1:], env))
}

// rlimitEnv carries the encoded limits of the class from `run` to the stub; the
// stub removes it before the program starts.
const rlimitEnv = "__SDCREDS_RLIMITS"

var limitsApply = applyLimits

// passFDEnv carries the --pass-fd numbers (comma separated) from `run` to the
// stub, which keeps those descriptors open and removes the variable.
const passFDEnv = "__SDCREDS_PASSFD"

// maxPassFD is the highest descriptor --pass-fd accepts.
const maxPassFD = 1023

// parsePassFDs reads the descriptors the stub must keep; none when the variable
// is absent. A number the stub could not have been given is an error.
func parsePassFDs(env []string) ([]int, error) {
	var keep []int
	for _, e := range env {
		v, ok := strings.CutPrefix(e, passFDEnv+"=")
		if !ok {
			continue
		}
		for _, s := range strings.Split(v, ",") {
			n, err := strconv.Atoi(s)
			if err != nil || n < 4 || n > maxPassFD {
				return nil, fmt.Errorf("%s: %q is not a descriptor", passFDEnv, s)
			}
			keep = append(keep, n)
		}
	}
	return keep, nil
}

// stubFiles is the ExtraFiles of the stub: the gate at descriptor 3 (entry 0),
// and each --pass-fd descriptor at the same number (entry fd-3; the entries in
// between stay nil, so those descriptors are closed in the stub). The numbers
// are handed to the stub in env so that it keeps them.
func stubFiles(gate *os.File, fds []int, env *[]string) []*os.File {
	files := []*os.File{gate}
	if len(fds) == 0 {
		return files
	}
	var names []string
	for _, fd := range fds {
		for len(files) <= fd-3 {
			files = append(files, nil)
		}
		files[fd-3] = os.NewFile(uintptr(fd), "passed-fd")
		names = append(names, strconv.Itoa(fd))
	}
	*env = append(*env, passFDEnv+"="+strings.Join(names, ","))
	return files
}

// maxCloseFD bounds the descriptor scan when the limit is unlimited.
const maxCloseFD = 65536

// Seams for the tests.
var (
	closeFrom = func(from int) {
		var rl syscall.Rlimit
		top := maxCloseFD
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil && rl.Cur < uint64(top) {
			top = int(rl.Cur)
		}
		for fd := from; fd < top; fd++ {
			_ = syscall.Close(fd)
		}
	}
	// closeExcept closes every descriptor from from up except those of keep.
	closeExcept = func(from int, keep []int) {
		var rl syscall.Rlimit
		top := maxCloseFD
		if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err == nil && rl.Cur < uint64(top) {
			top = int(rl.Cur)
		}
		for fd := from; fd < top; fd++ {
			if !slices.Contains(keep, fd) {
				_ = syscall.Close(fd)
			}
		}
	}
	umask = func(m int) { syscall.Umask(m) }
)

func addHelperCmds(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use: stubCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error { return failed(execGate(args)) },
	}, &cobra.Command{
		Use: delivery.KillCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			osExit(delivery.KillMain(args))
			return nil
		},
	}, &cobra.Command{
		Use: delivery.HelperCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return delivery.ServeMFS(args, os.NewFile(3, "ctl"))
		},
	})
}

// defaultPath is the PATH the program gets; the caller's is not inherited.
const defaultPath = "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin"

// stubEnv is the environment of the program: the locale and the terminal are
// kept, PATH is fixed, and the credentials directory is added. Nothing else of
// the caller's environment reaches a process that runs as another user.
//
// pass names further variables of env to hand on (--pass-env); one that is not
// set is not passed, and the names sdcreds owns are never taken from env.
func stubEnv(env []string, credDir string, pass ...string) []string {
	out := []string{"PATH=" + defaultPath, delivery.EnvVar + "=" + credDir}
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if !ok || ownedEnvName(name) {
			continue
		}
		if name == "LANG" || name == "TZ" || name == "TERM" || strings.HasPrefix(name, "LC_") || slices.Contains(pass, name) {
			out = append(out, e)
		}
	}
	return out
}

// ownedEnvName is a variable sdcreds sets itself: PATH, the credentials
// directory and its own `__SDCREDS_` channel to the stub.
func ownedEnvName(name string) bool {
	return name == "PATH" || name == delivery.EnvVar || strings.HasPrefix(name, "__SDCREDS_")
}

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)

var (
	errPassEnvOwned = errors.New("--pass-env: the variable is set by sdcreds itself")
	errPassEnvName  = errors.New("--pass-env: not a variable name")
	errPassFDOwned  = errors.New("--pass-fd: descriptors 0-3 belong to sdcreds and the program's standard streams")
	errPassFDClosed = errors.New("--pass-fd: the descriptor is not open")
	errPassFDOwn    = errors.New("--pass-fd: the descriptor is close-on-exec, so it is sdcreds' own or not meant to be inherited")
	errPassFDRange  = errors.New("--pass-fd: descriptor out of range")
)

// fdFlags is fcntl(F_GETFD); a seam for the tests.
var fdFlags = func(fd int) (int, error) { return unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0) }

// checkPassEnv judges the names of --pass-env.
func checkPassEnv(names []string) error {
	for _, n := range names {
		switch {
		case !envNameRE.MatchString(n):
			return fmt.Errorf("%w: %q", errPassEnvName, n)
		case ownedEnvName(n):
			return fmt.Errorf("%w: %s", errPassEnvOwned, n)
		}
	}
	return nil
}

// checkPassFDs judges the descriptors of --pass-fd, which are mapped to the same
// number in the program. 0-3 are the standard streams (already inherited) and the
// stub's gate; every descriptor sdcreds opens itself is close-on-exec, so only a
// descriptor that was handed to sdcreds to be inherited (not close-on-exec) is
// accepted, and it must be open now, before sdcreds opens anything.
func checkPassFDs(fds []int) error {
	for _, fd := range fds {
		switch {
		case fd < 0 || fd > maxPassFD:
			return fmt.Errorf("%w: %d", errPassFDRange, fd)
		case fd <= 3:
			return fmt.Errorf("%w: %d", errPassFDOwned, fd)
		}
		fl, err := fdFlags(fd)
		if err != nil {
			return fmt.Errorf("%w: %d", errPassFDClosed, fd)
		}
		if fl&unix.FD_CLOEXEC != 0 {
			return fmt.Errorf("%w: %d", errPassFDOwn, fd)
		}
	}
	return nil
}
