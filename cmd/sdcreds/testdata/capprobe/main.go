//go:build linux

// capprobe is the service of the --keep-cap integration test: it prints what the
// kernel says about its own privileges, then tries the two ways back that the
// securebits and no_new_privs are there to shut. With "hold" it then waits to be
// killed, so that the test can look at its parent.
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

const (
	prGetSecurebits = 27
	prSetSecurebits = 28
	prCapAmbient    = 47
)

func main() {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	for _, l := range strings.Split(string(status), "\n") {
		for _, k := range []string{"Uid:", "Gid:", "NoNewPrivs:", "CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"} {
			if strings.HasPrefix(l, k) {
				fmt.Println(l)
			}
		}
	}
	bits, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prGetSecurebits, 0, 0)
	fmt.Printf("securebits: %#x (%v)\n", bits, e)
	// The securebits are locked: clearing them is refused, whatever this
	// process holds.
	_, _, e = syscall.RawSyscall(syscall.SYS_PRCTL, prSetSecurebits, 0, 0)
	fmt.Printf("clear securebits: %v\n", e)
	// Getting root back is refused: no capability lets this process setuid.
	fmt.Printf("setuid 0: %v\n", syscall.Setuid(0))
	// An ambient capability that was never kept cannot be raised (CAP_SYS_ADMIN).
	_, _, e = syscall.RawSyscall6(syscall.SYS_PRCTL, prCapAmbient, 2, 21, 0, 0, 0)
	fmt.Printf("raise CAP_SYS_ADMIN: %v\n", e)
	if len(os.Args) > 1 && os.Args[1] == "hold" {
		fmt.Println("ready")
		time.Sleep(time.Minute)
	}
}
