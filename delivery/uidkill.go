//go:build unix

package delivery

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// The release kill never signals a pid read from a list. A pid taken from the
// process table can be given to another process between the reading and the
// signal (a zombie reaped by init, a pid reused), and root would then kill a
// stranger. The kernel walks its own table instead: kill(-1, SIGKILL) reaches
// every process the sender may signal, and nothing else. The sender is a
// "killer" with split credentials (see KillMain): it can signal every process of
// the target user, and no process of the target can signal it.

// procOps is what the release kill needs from the system; the tests give it a
// scripted process table.
type procOps struct {
	// list returns the live processes whose real, effective or saved uid is uid:
	// what makes a start refuse AND what the release is judged by, so that a
	// process that holds the user's rights by any of the three cannot outlive
	// the release unseen and block the next start. It is only ever read.
	list func(uid int) ([]proc, error)
	// kill runs one killer for at most wait and returns its exit status.
	kill  func(wait time.Duration) (int, error)
	sleep func(time.Duration)
	now   func() time.Time
}

const (
	// rootKillBudget is how long the release keeps trying: a process that is not
	// gone by then is one the killer cannot reach, and the caller is told.
	rootKillBudget = 20 * time.Second
	// killTotal is the longest KillUID takes: the wait for the other killers (one
	// at a time), then its own budget, plus the time to reap a killer.
	killTotal = 2*rootKillBudget + time.Second
	killPause = 50 * time.Millisecond
)

// Exit statuses of KillMain.
const (
	killExitSurvives = 4  // kill(-1) still found something after the time allowed
	killExitUsage    = 64 // wrong arguments, or not started as root
	killExitCreds    = 65 // the split credentials could not be installed
)

// ErrKiller is a killer identity that cannot be used: the kill refuses to run
// rather than run with the wrong credentials.
var ErrKiller = errors.New("delivery: the killer user cannot be used")

// KillerUser is the dedicated system user whose uid is the real and saved uid of
// the killer. It must exist, must not be root, must not be a target, and must own
// no process (so that kill(-1) from a process of the target cannot reach it, and
// the killer does not reach root). It is an install requirement of the OpenBSD
// delivery: create it once, for example
//
//	useradd -s /sbin/nologin -d /var/empty -c "sdcreds killer" _sdkill
var KillerUser = "_sdkill"

// parseKillArgs reads the arguments of KillCommand: "kill UID KILLERUID KILLERGID".
// A uid of 0, a killer that is the target and ids that are not plain numbers are
// refused: kill(-1) with the real uid 0 is every process of the machine, and with
// the real uid of the target it is the weaker killer a target can stop.
func parseKillArgs(args []string) (uid, killer, gid int, err error) {
	if len(args) != 4 || args[0] != "kill" {
		return 0, 0, 0, errors.New("usage: kill UID KILLERUID KILLERGID")
	}
	ids := make([]int, 3)
	for i, s := range args[1:] {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("%q is not an id", s)
		}
		if err := ValidID(n, "id"); err != nil {
			return 0, 0, 0, err
		}
		ids[i] = int(n)
	}
	if ids[1] == ids[0] {
		return 0, 0, 0, errors.New("the killer uid is the target uid")
	}
	return ids[0], ids[1], ids[2], nil
}

// checkKiller refuses a killer identity that would make the kill unsafe or
// useless: root (ValidID), the target itself, or a user that owns a process,
// which the target's processes could then signal or which would be signalled.
func checkKiller(uid, killer int, list func(uid int) ([]proc, error)) error {
	if err := ValidID(int64(killer), "killer uid"); err != nil {
		return fmt.Errorf("%w: %w", ErrKiller, err)
	}
	if killer == uid {
		return fmt.Errorf("%w: uid %d is the target", ErrKiller, killer)
	}
	ps, err := list(killer)
	if err != nil {
		return fmt.Errorf("delivery: listing the processes of the killer uid %d: %w", killer, err)
	}
	if len(ps) > 0 {
		return fmt.Errorf("%w: uid %d owns process %d (it must own none)", ErrKiller, killer, ps[0].pid)
	}
	return nil
}

// killAllOf makes every process of uid go. Each pass is one killer that signals
// by kill(-1); the process table is only read, by root, to decide whether another
// pass is needed. A killer that died, was refused or found nothing it can reach is
// "run again": the table decides, and what is still there at the budget is
// ErrUIDSurvives (fail closed).
func killAllOf(uid int, o procOps) error {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return err
	}
	deadline := o.now().Add(rootKillBudget)
	var lastErr error
	for {
		ps, err := o.list(uid)
		if err != nil {
			return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
		}
		if len(ps) == 0 {
			return nil
		}
		left := deadline.Sub(o.now())
		if left <= 0 {
			err := fmt.Errorf("%w (uid %d)", ErrUIDSurvives, uid)
			if lastErr != nil {
				err = errors.Join(err, lastErr)
			}
			return err
		}
		code, kerr := o.kill(left)
		switch {
		case code == killExitUsage || code == killExitCreds:
			// The killer was refused or could not take its credentials: another
			// pass would be the same.
			return fmt.Errorf("%w: the killer exited %d (uid %d)", ErrKiller, code, uid)
		case kerr != nil:
			lastErr = kerr
		}
		o.sleep(killPause)
	}
}

// killerLockPath is the one lock that serializes the killers of this machine: all
// killers share a real uid, so two at once would signal each other.
var killerLockPath = "/var/run/sdcreds-killer.lock"

// lockKiller takes the machine-wide killer lock, waiting up to wait. The file is
// opened without following links and must be a plain file of the caller's, so a
// planted link or file cannot stand in for the lock.
func lockKiller(path string, wait time.Duration) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, fmt.Errorf("delivery: the killer lock %s: %w", path, err)
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || int(st.Uid) != os.Geteuid() || st.Mode&0o077 != 0 {
		f.Close()
		return nil, fmt.Errorf("delivery: the killer lock %s is not a private file of this user", path)
	}
	deadline := time.Now().Add(wait)
	for {
		err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) || !time.Now().Before(deadline) {
			f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, fmt.Errorf("%w: another release holds the killer lock", ErrBusy)
			}
			return nil, fmt.Errorf("delivery: the killer lock %s: %w", path, err)
		}
		time.Sleep(lockPoll)
	}
}

// onlyProcess reports ErrUIDBusy unless pid is the one process of uid, and is
// listed: an empty table is not the program being alone, it is a table that does
// not show the program, which a wrong layout would produce.
func onlyProcess(uid, pid int, o procOps) error {
	pids, err := o.list(uid)
	if err != nil {
		return fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
	}
	found := false
	for _, p := range pids {
		if p.pid != pid {
			return fmt.Errorf("%w: uid %d has process %d besides the program", ErrUIDBusy, uid, p.pid)
		}
		found = true
	}
	if !found {
		return fmt.Errorf("%w: the process table of uid %d does not list the program (pid %d)", ErrUIDBusy, uid, pid)
	}
	return nil
}

// busyOf reports whether uid has any process.
func busyOf(uid int, o procOps) (bool, error) {
	pids, err := o.list(uid)
	if err != nil {
		return false, fmt.Errorf("delivery: listing the processes of uid %d: %w", uid, err)
	}
	return len(pids) > 0, nil
}
