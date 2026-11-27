package delivery

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	"github.com/go-authn/sdcreds/internal/exitguard"
)

// KillCommand is the hidden command of the program that embeds this package: the
// killer. It is started by root with no credential change, so no process of the
// target can signal it while it is still root, and it then takes split
// credentials (see KillMain) before it signals anything.
const KillCommand = "__sdcreds-killuid"

// ErrUIDBusy is a target user that already has processes: the delivery refuses
// to start, because it will kill every process of that user when it ends.
var ErrUIDBusy = errors.New("delivery: the target user already has processes (a delivery owns its user exclusively)")

// ErrUIDSurvives is a target user some of whose processes survived SIGKILL.
var ErrUIDSurvives = errors.New("delivery: processes of the target user survived SIGKILL")

// becomeKiller turns the calling process (root) into the killer: a session of its
// own, no supplementary group, the killer's group, and the split credentials
// real uid = saved uid = killer, effective uid = target, in ONE setresuid. By the
// kernel's cansignal() it then reaches every process whose real or saved uid is
// the target (or the killer), and a process of the target, whose uid is not the
// killer's, cannot signal it. The result is read back before it is trusted.
func becomeKiller(uid, killer, gid int) error {
	if _, err := unix.Setsid(); err != nil && !errors.Is(err, unix.EPERM) {
		return err // EPERM: already a session leader, which is as good
	}
	if err := unix.Setgroups(nil); err != nil {
		return err
	}
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err := unix.Setresuid(killer, uid, killer); err != nil {
		return err
	}
	r, e, s := unix.Getresuid()
	if r != killer || e != uid || s != killer {
		return fmt.Errorf("delivery: the killer has uids %d/%d/%d, want %d/%d/%d", r, e, s, killer, uid, killer)
	}
	return nil
}

// KillMain is the body of KillCommand; args is "kill UID KILLERUID KILLERGID". It
// returns the exit status. It must start as root (it installs the credentials)
// and refuses a killer uid of 0 or of the target: with the real uid 0, kill(-1)
// would reach every root process, and with the target's it is the killer a
// target can stop.
//
// It signals nothing but kill(-1, SIGKILL): the kernel walks its own process
// table, so no pid crosses user space and none can be reused. It loops until the
// kernel answers ESRCH (nothing left that it may signal), within rootKillBudget.
func KillMain(args []string) int {
	uid, killer, gid, err := parseKillArgs(args)
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return killExitUsage
	}
	if err := becomeKiller(uid, killer, gid); err != nil {
		return killExitCreds
	}
	deadline := time.Now().Add(rootKillBudget)
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

// runKiller runs `exe KillCommand kill UID KILLERUID KILLERGID` as root, for at
// most wait, and returns its exit status. On the timeout the child, root's own,
// is killed through exitguard.Run, never after it has been reaped: the pid may be
// somebody else's by then, and exec.CommandContext's kill can arrive in that
// window on OpenBSD (see exitguard).
func runKiller(exe string, uid, killer, gid int, wait time.Duration) (int, error) {
	cmd := exec.Command(exe, KillCommand, "kill", strconv.Itoa(uid), strconv.Itoa(killer), strconv.Itoa(gid))
	cmd.Env = []string{}
	err := exitguard.Run(cmd, wait+time.Second)
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
	// The saved uid is read at an offset no selector confirms: this process's own
	// three ids must come back as getresuid(2) gives them.
	r, e, s := unix.Getresuid()
	pid := os.Getpid()
	_, err = listKernWith(kernProcAll, 0, func(buf []byte) ([]proc, error) { return nil, checkOwnIDs(buf, pid, r, e, s) })
	return err
}

// realProcs reads the process table; it has no way to signal.
var realProcs = procOps{
	list:  listUID,
	sleep: time.Sleep,
	now:   time.Now,
}

// UIDBusy reports whether the user has any process, read by root from the
// process table.
func UIDBusy(uid int) (bool, error) { return busyOf(uid, realProcs) }

// VerifyOnlyProcess is ErrUIDBusy unless pid is the only process of uid; the
// caller makes it just before it lets the program run.
func VerifyOnlyProcess(uid, pid int) error { return onlyProcess(uid, pid, realProcs) }

// lookupKiller finds the killer user's uid and gid (a seam for the tests).
var lookupKiller = func() (uid, gid int, err error) {
	u, err := user.Lookup(KillerUser)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: user %q: %v (create it: useradd -s /sbin/nologin -d /var/empty -c \"sdcreds killer\" %s)", ErrKiller, KillerUser, err, KillerUser)
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("%w: user %q has uid %q and gid %q", ErrKiller, KillerUser, u.Uid, u.Gid)
	}
	return uid, gid, nil
}

// killerIDs is the killer identity for a delivery to uid, refused unless it can
// be used: it exists, is not root and is not the target. That it owns no process
// is checked at the start (checkKillerAtStart), not here: the killer of a release
// that is running owns one.
func killerIDs(uid int) (killer, gid int, err error) {
	killer, gid, err = lookupKiller()
	if err != nil {
		return 0, 0, err
	}
	if _, _, _, err := parseKillArgs([]string{"kill", strconv.Itoa(uid), strconv.Itoa(killer), strconv.Itoa(gid)}); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrKiller, err)
	}
	return killer, gid, nil
}

// KillUID makes every process of the user go. The caller is root. One at a time
// per user (a kill of another user never makes this one wait or give up), a killer with split credentials sends SIGKILL by kill(-1) until the kernel has
// nothing left it may signal; root only reads the process table, to run it again
// or to report ErrUIDSurvives after the budget. gid and groups are the target's
// and no longer used: the killer takes the group of the killer user.
func KillUID(exe string, uid, gid int, groups []int) error {
	if err := ValidID(int64(uid), "uid"); err != nil {
		return err
	}
	killer, kgid, err := killerIDs(uid)
	if err != nil {
		return err
	}
	// No "owns no process" check here: the killer of a release of another user
	// runs at this very moment and owns one. The start made that check
	// (checkKillerAtStart), and a killer user that owns a process is not a reason
	// to leave the target's processes alive.
	o := realProcs
	o.kill = func(wait time.Duration) (int, error) { return runKiller(exe, uid, killer, kgid, wait) }
	return killLocked(uid, killerLockFile(uid), killLockWait, o)
}
