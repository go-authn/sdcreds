//go:build unix

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

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
	closeFrom(3)
	umask(0o077)
	// The limits of the login class, if --class asked for them: a limit that
	// cannot be applied means the program does not run.
	env := os.Environ()
	spec := ""
	for _, e := range env {
		if v, ok := strings.CutPrefix(e, rlimitEnv+"="); ok {
			spec = v
		}
	}
	env = envWithout(env, rlimitEnv)
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
	umask = func(m int) { syscall.Umask(m) }
)

func addHelperCmds(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use: stubCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error { return execGate(args) },
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
func stubEnv(env []string, credDir string) []string {
	out := []string{"PATH=" + defaultPath, delivery.EnvVar + "=" + credDir}
	for _, e := range env {
		name, _, ok := strings.Cut(e, "=")
		if ok && (name == "LANG" || name == "TZ" || name == "TERM" || strings.HasPrefix(name, "LC_")) {
			out = append(out, e)
		}
	}
	return out
}
