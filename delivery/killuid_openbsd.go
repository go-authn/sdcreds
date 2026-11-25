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
// run as the TARGET user, it signals every process that user can signal. A
// process of the target cannot hide from it by calling setsid, setpgid or by
// daemonizing, which a kill by process group cannot say.
const KillCommand = "__sdcreds-killuid"

// Exit statuses of KillMain.
const (
	killExitAlive    = 3 // probe: the user has other processes
	killExitSurvives = 4 // kill: some are still there after the time allowed
	killExitUsage    = 64
)

// killBudget is how long one KillMain keeps signalling: a process that forks
// faster than it is killed is stopped by the login class limits, not by this.
const killBudget = 4 * time.Second

// ErrUIDBusy is a target user that already has processes: the delivery refuses
// to start, because it will kill every process of that user when it ends.
var ErrUIDBusy = errors.New("delivery: the target user already has processes (a delivery owns its user exclusively)")

// ErrUIDSurvives is a target user some of whose processes survived SIGKILL.
var ErrUIDSurvives = errors.New("delivery: processes of the target user survived SIGKILL")

// KillMain is the body of KillCommand; args is "probe" or "kill". It returns
// the exit status. It refuses to run with uid or euid 0: kill(-1) as root is
// every process of the machine.
func KillMain(args []string) int {
	if len(args) != 1 || os.Getuid() == 0 || os.Geteuid() == 0 {
		return killExitUsage
	}
	switch args[0] {
	case "probe":
		switch err := unix.Kill(-1, 0); {
		case err == nil:
			return killExitAlive
		case errors.Is(err, unix.ESRCH):
			return 0
		}
		return 1
	case "kill":
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
	return killExitUsage
}

// runKiller runs `exe KillCommand mode` as the target user and returns its
// exit status.
func runKiller(exe, mode string, uid, gid int, groups []int) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), killBudget+3*time.Second)
	defer cancel()
	gs := make([]uint32, len(groups))
	for i, g := range groups {
		gs[i] = uint32(g)
	}
	cmd := exec.CommandContext(ctx, exe, KillCommand, mode)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid), Groups: gs}}
	err := cmd.Run()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &ee) && ee.ExitCode() >= 0:
		return ee.ExitCode(), nil
	case errors.As(err, &ee):
		// ended by a signal: name it, instead of reporting a status of -1
		return -1, fmt.Errorf("the %s child ended abnormally: %w", mode, err)
	}
	return -1, err
}

// UIDBusy reports whether the user has any process, by asking a child that runs
// as that user. exe is the program that embeds this package.
func UIDBusy(exe string, uid, gid int, groups []int) (bool, error) {
	code, err := runKiller(exe, "probe", uid, gid, groups)
	switch {
	case err != nil:
		return false, fmt.Errorf("delivery: probing the processes of uid %d: %w", uid, err)
	case code == 0:
		return false, nil
	case code == killExitAlive:
		return true, nil
	}
	return false, fmt.Errorf("delivery: probing the processes of uid %d: status %d", uid, code)
}

// killRounds is how many times KillUID starts a killer: a process of the target
// can signal the killer, as they share a user, and the next round goes on.
const killRounds = 4

// KillUID sends SIGKILL to every process of the user, repeatedly, until none is
// left, and returns ErrUIDSurvives if some are. The caller is root, and the
// killer is a child that has dropped to the target user: only a process of that
// user is ever signalled.
func KillUID(exe string, uid, gid int, groups []int) error {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return err
	}
	var last error = ErrUIDSurvives
	for i := 0; i < killRounds; i++ {
		code, err := runKiller(exe, "kill", uid, gid, groups)
		switch {
		case err != nil:
			last = fmt.Errorf("delivery: killing the processes of uid %d: %w", uid, err)
		case code == 0:
			return nil
		case code == killExitSurvives:
			last = fmt.Errorf("%w (uid %d)", ErrUIDSurvives, uid)
		default:
			last = fmt.Errorf("delivery: killing the processes of uid %d: status %d", uid, code)
		}
	}
	return last
}
