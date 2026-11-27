package delivery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// KillCommand is the hidden command of the program that embeds this package:
// run as the TARGET user, it signals every process that user can signal. It is
// only the fast, race-free first move of KillUID: a process of the target can
// signal it, so root (KillUID's second move) is what decides.
const KillCommand = "__sdcreds-killuid"

// Exit statuses of KillMain.
const (
	killExitSurvives = 4 // some are still there after the time allowed
	killExitUsage    = 64
)

// killBudget is how long one KillMain keeps signalling.
const killBudget = time.Second

// ErrUIDBusy is a target user that already has processes: the delivery refuses
// to start, because it will kill every process of that user when it ends.
var ErrUIDBusy = errors.New("delivery: the target user already has processes (a delivery owns its user exclusively)")

// ErrUIDSurvives is a target user some of whose processes survived SIGKILL.
var ErrUIDSurvives = errors.New("delivery: processes of the target user survived SIGKILL")

// KillMain is the body of KillCommand; args is "kill". It returns the exit
// status. It refuses to run with uid or euid 0: kill(-1) as root is every
// process of the machine.
func KillMain(args []string) int {
	if len(args) != 1 || args[0] != "kill" || os.Getuid() == 0 || os.Geteuid() == 0 {
		return killExitUsage
	}
	deadline := time.Now().Add(killBudget)
	for {
		err := unix.Kill(-1, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return 0
		}
		if time.Now().After(deadline) {
			return killExitSurvives
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// runKiller runs `exe KillCommand kill` as the target user and returns its exit
// status.
func runKiller(exe string, uid, gid int, groups []int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), killBudget+time.Second)
	defer cancel()
	gs := make([]uint32, len(groups))
	for i, g := range groups {
		gs[i] = uint32(g)
	}
	cmd := exec.CommandContext(ctx, exe, KillCommand, "kill")
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: gs}}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode(), nil
	}
	return -1, err
}

// The process table, from sysctl(3) kern.proc: the kernel fills one struct
// kinfo_proc per process, of the size asked for; the layout is in kinfo.go.
const (
	procChunk = 1024
	procMax   = 1 << 20
)

// listKern returns the pids that sysctl kern.proc reports for one selector.
func listKern(op, id int) ([]proc, error) {
	return listKernWith(op, id, func(buf []byte) ([]proc, error) { return parseKinfo(buf, op, id) })
}

// listKernWith is listKern with the reading of the answer left to parse.
func listKernWith(op, id int, parse func([]byte) ([]proc, error)) ([]proc, error) {
	for count := procChunk; count <= procMax; count *= 2 {
		buf, err := unix.SysctlRaw("kern.proc", op, id, kinfoSize, count)
		if err != nil {
			return nil, err
		}
		n := len(buf) / kinfoSize
		if n >= count {
			continue // the table may be larger than the room asked for
		}
		return parse(buf)
	}
	return nil, errors.New("the process table is larger than the limit")
}

// listUID is every process whose real, effective OR saved uid is uid: the real
// uid is what the target's processes have; a program that runs with the target
// as its effective or saved uid only (a set-uid file of that user) is the same
// user to this delivery. The start check and the kill both go by this set. The
// kernel selects by real and effective uid; the saved uid is found by reading
// every process (KERN_PROC_ALL).
func listUID(uid int) ([]proc, error) {
	var all []proc
	add := func(ps []proc) {
		for _, p := range ps {
			if !containsPid(all, p.pid) {
				all = append(all, p)
			}
		}
	}
	for _, op := range []int{kernProcRUID, kernProcUID} {
		ps, err := listKern(op, uid)
		if err != nil {
			return nil, err
		}
		add(ps)
	}
	ps, err := listKernWith(kernProcAll, 0, func(buf []byte) ([]proc, error) { return parseKinfoAll(buf, uid) })
	if err != nil {
		return nil, err
	}
	add(ps)
	return all, nil
}

func containsPid(s []proc, pid int) bool {
	for _, x := range s {
		if x.pid == pid {
			return true
		}
	}
	return false
}

// checkProcLayout fails unless the process table lists this very process under
// its own uid: a kernel whose struct kinfo_proc differs from the one this was
// written for would otherwise read garbage, and the kill would do nothing.
func checkProcLayout() error {
	ps, err := listUID(os.Getuid())
	if err != nil {
		return fmt.Errorf("delivery: reading the process table: %w", err)
	}
	if !containsPid(ps, os.Getpid()) {
		return errors.New("delivery: the process table does not list this process: struct kinfo_proc is not the one expected")
	}
	return nil
}

var realProcs = procOps{
	list:   listUID,
	signal: func(pid int, sig syscall.Signal) error { return unix.Kill(pid, sig) },
	sleep:  time.Sleep,
	now:    time.Now,
}

// UIDBusy reports whether the user has any process, read by root from the
// process table.
func UIDBusy(uid int) (bool, error) { return busyOf(uid, realProcs) }

// VerifyOnlyProcess is ErrUIDBusy unless pid is the only process of uid; the
// caller makes it just before it lets the program run.
func VerifyOnlyProcess(uid, pid int) error { return onlyProcess(uid, pid, realProcs) }

// KillUID makes every process of the user go. The caller is root. First, one
// killer that has dropped to the target user sends SIGKILL to the user's
// processes without a pid race; a process of the target may kill it, so the
// outcome is not taken from it. Then root stops, re-reads and kills by the
// process table until the user has no process, and returns ErrUIDSurvives if
// some are left after the budget.
func KillUID(exe string, uid, gid int, groups []int) error {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return err
	}
	_ = giveUpAfter(killBudget+time.Second, func() { _, _ = runKiller(exe, uid, gid, groups) })
	return killAllOf(uid, realProcs)
}
