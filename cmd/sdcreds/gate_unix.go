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
	prog := args[1]
	return fmt.Errorf("exec %s: %w", prog, execProgram(prog, args[1:], os.Environ()))
}

func addHelperCmds(root *cobra.Command) {
	root.AddCommand(&cobra.Command{
		Use: stubCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error { return execGate(args) },
	}, &cobra.Command{
		Use: delivery.HelperCommand, Hidden: true, DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return delivery.ServeMFS(args, os.NewFile(3, "ctl"))
		},
	})
}
