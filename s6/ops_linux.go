//go:build linux

package s6

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Seams for the tests: the failures of these calls cannot be provoked on a
// real system, and what each caller does with them (return the error, leave
// nothing mounted, restore the thread) is the point of the tests.
var (
	userLookup    = user.Lookup
	groupIDs      = func(u *user.User) ([]string, error) { return u.GroupIds() }
	sysUnshare    = syscall.Unshare
	sysMount      = syscall.Mount
	sysUnmount    = syscall.Unmount
	sysAccess     = syscall.Access
	sysGetgroups  = syscall.Getgroups
	sysRaw        = syscall.RawSyscall
	sysRaw6       = syscall.RawSyscall6
	prctlCall     = prctl
	capGet        = unix.Capget
	capSet        = unix.Capset
	sysStatfs     = syscall.Statfs
	mountinfoPath = "/proc/thread-self/mountinfo"
)

// msNoSymFollow is MS_NOSYMFOLLOW (linux/mount.h), absent from package syscall.
const msNoSymFollow = 1 << 8

const hardening = syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID | msNoSymFollow

// Real returns the Linux implementation; it needs root.
func Real() Ops {
	return Ops{
		LookupUser: lookupUser,
		Unshare:    unshare,
		MountRAM:   mountRAM,
		Chown:      os.Lchown,
		RemountRO:  remountRO,
		Unmount:    unmount,
		Start:      start,
		StartSignals: func(held <-chan os.Signal, u User, argv, env []string) (func() (int, error), error) {
			return startWith(held, func() {}, u, argv, env)
		},
		Resolve:     exec.LookPath,
		Move:        move,
		FSType:      fsType,
		CanExec:     canExec,
		MountSource: mountSource,
	}
}

// lookupUser resolves the account with os/user. Built without cgo (the usual
// static build) that reads /etc/passwd and /etc/group only, with no NSS: the
// supplementary groups that LDAP or SSSD would give are then missing.
func lookupUser(name string) (User, error) {
	u, err := userLookup(name)
	if err != nil {
		return User{}, err
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return User{}, err
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil {
		return User{}, err
	}
	out := User{UID: uid, GID: gid}
	ids, err := groupIDs(u)
	if err != nil {
		return User{}, err
	}
	for _, s := range ids {
		g, err := strconv.Atoi(s)
		if err != nil {
			return User{}, err
		}
		out.Groups = append(out.Groups, g)
	}
	return out, nil
}

// unshare moves this thread into a new mount namespace whose mounts do not
// propagate back to the host.
func unshare() error {
	if err := sysUnshare(syscall.CLONE_NEWNS); err != nil {
		return err
	}
	return sysMount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
}

// mountRAM mounts a tmpfs that never swaps (noswap, Linux 6.4), sized for the
// credentials; on a kernel that does not know noswap it mounts a ramfs, which
// cannot swap either and whose size is bounded by what Run writes into it.
func mountRAM(dir string) error {
	target, release, err := pin(dir)
	if err != nil {
		return err
	}
	defer release()
	data := fmt.Sprintf("noswap,mode=0700,size=%d,nr_inodes=%d", MaxTotal+(1<<20), MaxEntries+16)
	// The file-system name is the marker of the mounts of this package.
	// Success, or a refusal that is final; only EINVAL (no noswap) tries the ramfs.
	if err := sysMount(MountTag, target, "tmpfs", hardening, data); !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return sysMount(MountTag, target, "ramfs", hardening, "mode=0700")
}

// mountSource reads the mount table of the calling thread for dir. Not
// /proc/self/mountinfo: that is the table of the thread-group leader, and Run
// unshares the mount namespace of its own (locked) thread only.
func mountSource(dir string) (string, bool, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false, err
	}
	table, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return "", false, err
	}
	src, mounted := mountSourceIn(string(table), real)
	return src, mounted, nil
}

// Real-id calls of one thread (not the whole process, as package syscall's
// Setresuid is): the thread that checks execution runs as the user for the
// length of the check and is restored.
func setThreadIDs(u User) (restore func() error, err error) {
	prev, err := sysGetgroups()
	if err != nil {
		return func() error { return nil }, err
	}
	restore = func() error {
		var errs []error
		for _, call := range []func() error{
			func() error { return rawSetres(trapSetresuid, 0, 0) },
			func() error { return rawSetres(trapSetresgid, 0, 0) },
			func() error { return rawSetgroups(prev) },
		} {
			errs = append(errs, call())
		}
		return errors.Join(errs...)
	}
	groups := u.Groups
	if len(groups) == 0 {
		groups = []int{u.GID}
	}
	if err := rawSetgroups(groups); err != nil {
		return restore, err
	}
	if err := rawSetres(trapSetresgid, u.GID, 0); err != nil {
		return restore, err
	}
	return restore, rawSetres(trapSetresuid, u.UID, 0)
}

// rawSetres sets the real and effective id of the calling thread to id and the
// saved id to saved (0 lets the thread go back to root).
func rawSetres(trap uintptr, id, saved int) error {
	if _, _, e := sysRaw(trap, uintptr(id), uintptr(id), uintptr(saved)); e != 0 {
		return e
	}
	return nil
}

func rawSetgroups(g []int) error {
	ids := make([]uint32, len(g))
	for i, v := range g {
		ids[i] = uint32(v)
	}
	var p unsafe.Pointer
	if len(ids) > 0 {
		p = unsafe.Pointer(&ids[0])
	}
	if _, _, e := sysRaw(trapSetgroups, uintptr(len(ids)), uintptr(p), 0); e != 0 {
		return e
	}
	return nil
}

// canExec asks the kernel whether u may execute path: a regular file, every
// directory of the path searchable and the file executable by u. The calling
// thread takes u's identity for the check and gets root back; if it cannot, it
// stays locked to the goroutine, which makes the runtime discard it.
func canExec(path string, u User) error {
	runtime.LockOSThread()
	restore, err := setThreadIDs(u)
	var aerr error
	if err == nil {
		aerr = sysAccess(path, 1) // X_OK, by the real id, which is u's now
	}
	if rerr := restore(); rerr != nil {
		return fmt.Errorf("could not restore the privileges of the thread: %w", rerr)
	}
	runtime.UnlockOSThread()
	if err != nil {
		return err
	}
	if aerr != nil {
		return aerr
	}
	st, err := os.Stat(path)
	if err == nil && !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return err
}

func remountRO(dir string) error {
	target, release, err := pin(dir)
	if err != nil {
		return err
	}
	defer release()
	return sysMount("", target, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|hardening, "")
}

// oPath is O_PATH (0o10000000 on every Linux architecture, asm-generic and x86
// alike), which package syscall defines only on some of them.
const oPath = 0o10000000

// pin opens dir without following a symbolic link and returns a path through
// the descriptor, which keeps naming that directory whatever happens to the
// name; release closes it.
func pin(dir string) (path string, release func(), err error) {
	fd, err := syscall.Open(dir, oPath|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return "", func() {}, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	return "/proc/self/fd/" + strconv.Itoa(fd), func() { syscall.Close(fd) }, nil
}

// move bind-mounts the (read-only, hardened) mount at src on dst, which keeps
// the flags of the mount, then detaches src. A bind and not MS_MOVE: a move is
// refused when the parent mount is shared, as it is under systemd.
func move(src, dst string) error {
	s, releaseS, err := pin(src)
	if err != nil {
		return err
	}
	defer releaseS()
	d, releaseD, err := pin(dst)
	if err != nil {
		return err
	}
	defer releaseD()
	if err := sysMount(s, d, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	return unmount(src)
}

// umountNoFollow is UMOUNT_NOFOLLOW (sys/mount.h): never follow a final symlink.
const umountNoFollow = 0x8

func unmount(dir string) error {
	err := sysUnmount(dir, syscall.MNT_DETACH|umountNoFollow)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
		return ErrNotMounted
	}
	return err
}

// fsType names the file system at dir, by the magic numbers of statfs(2).
func fsType(dir string) (string, error) {
	var st syscall.Statfs_t
	if err := sysStatfs(dir, &st); err != nil {
		return "", &os.PathError{Op: "statfs", Path: dir, Err: err}
	}
	switch uint32(st.Type) {
	case 0x01021994:
		return "tmpfs", nil
	case 0x858458f6:
		return "ramfs", nil
	}
	return fmt.Sprintf("0x%x", uint32(st.Type)), nil
}

// prctl(2) options used by dropPrivileges.
const (
	prCapbsetRead   = 23
	prCapbsetDrop   = 24
	prSetNoNewPrivs = 38
	prSetSecurebits = 28
	capLastCapMax   = 63
)

func prctl(option, arg2 uintptr) (uintptr, error) {
	r, _, errno := sysRaw6(syscall.SYS_PRCTL, option, arg2, 0, 0, 0, 0)
	if errno != 0 {
		return 0, errno
	}
	return r, nil
}

// restrictThread runs on a locked thread that is never given back to the
// runtime and that forks the service: no_new_privs and the bounding set belong
// to the thread, and a forked child and its exec inherit them. The service can
// neither gain privileges from a set-user-id file nor get back a capability.
// The ids are not changed here: this thread and its process stay root, and the
// child alone takes the identity of the service (SysProcAttr.Credential), so no
// thread of the parent carries ids the service could act through.
//
// With keep empty that is all, as in v0.1.0. With keep (the allowlisted
// capabilities of --keep-cap) the bounding set is reduced to exactly keep
// instead of emptied, and the thread is prepared so that its child ends up with
// exactly keep in its permitted, inheritable, effective and ambient sets, in the
// order capabilities(7) and prctl(2) need:
//
//  1. no_new_privs, first, so that nothing below can be undone by an exec.
//  2. The bounding set is cut down to keep (PR_CAPBSET_DROP, CAP_SETPCAP).
//     capabilities(7): the bounding set limits what exec may add to the
//     permitted set and what capset may add to the inheritable set, so it is
//     cut before and never grown.
//  3. The inheritable set of the thread becomes keep (capset(2): the new
//     inheritable set must be inside the old inheritable set plus the bounding
//     set, which keep is). An ambient capability must be in both the permitted
//     and the inheritable set (prctl(2), PR_CAP_AMBIENT_RAISE), and the
//     inheritable set passes through exec unchanged, so it is exactly keep.
//  4. The securebit NOROOT is set and locked (PR_SET_SECUREBITS,
//     capabilities(7) "The securebits flag"), and a child inherits it across
//     fork and exec: the service can never turn it off (the _LOCKED bit is
//     irrevocable), so a uid 0 it might later reach gets no capability from
//     being root. NO_SETUID_FIXUP is left clear (see secbitsLocked), so that the
//     child's effective set is emptied by its setuid and a service started
//     with a kept capability cannot read a root-only file before its exec.
//
// The child's own part is SysProcAttr.AmbientCaps (see launch). Go's child sets
// SECBIT_KEEP_CAPS before it changes uid, so the permitted set survives
// setuid(2) (capabilities(7) "Effect of user ID changes on capabilities"),
// then adds keep to the permitted and inheritable sets and raises each in the
// ambient set. At execve(2) the permitted set of an unprivileged uid with no
// file capabilities is the ambient set, and the effective set is the same: P'(perm)
// = (P(inh) & F(inh)) | (F(perm) & bounding) | P'(amb), so permitted and
// effective end up exactly keep, bounded by the bounding set, however large the
// permitted set of the launcher was. This thread's permitted and effective sets
// are not changed: the thread stays root with its own capabilities, and the
// parent process is untouched.
func restrictThread(keep []Cap) error {
	if _, err := prctlCall(prSetNoNewPrivs, 1); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	kept := 0
	for c := uintptr(0); c <= capLastCapMax; c++ {
		if _, err := prctlCall(prCapbsetRead, c); err != nil {
			if errors.Is(err, syscall.EINVAL) {
				break // past the last capability of this kernel
			}
			return fmt.Errorf("capability bounding set: %w", err)
		}
		if slices.Contains(keep, Cap(c)) {
			kept++
			continue
		}
		if _, err := prctlCall(prCapbsetDrop, c); err != nil {
			return fmt.Errorf("capability bounding set: %w", err)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	if kept != len(keep) {
		return errors.New("capability bounding set: the kernel does not know a capability that was asked to be kept")
	}
	if err := setInheritable(keep); err != nil {
		return fmt.Errorf("inheritable set: %w", err)
	}
	if _, err := prctlCall(prSetSecurebits, secbitsLocked); err != nil {
		return fmt.Errorf("securebits: %w", err)
	}
	return nil
}

// setInheritable makes the inheritable set of this thread exactly keep and
// leaves its permitted and effective sets as they are.
func setInheritable(keep []Cap) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := capGet(&hdr, &data[0]); err != nil {
		return err
	}
	data[0].Inheritable, data[1].Inheritable = 0, 0
	for _, c := range keep {
		data[c/32].Inheritable |= 1 << (uint(c) % 32)
	}
	return capSet(&hdr, &data[0])
}

// The securebits of prctl(2) PR_SET_SECUREBITS (linux/securebits.h).
const (
	secbitNoRoot       = 1 << 0
	secbitNoRootLocked = 1 << 1
	// secbitsLocked is what a service with kept capabilities runs under. Not
	// KEEP_CAPS: Go's child sets that itself around its setuid, and it is
	// cleared by execve(2) whatever is asked here. Not NO_SETUID_FIXUP either,
	// on purpose: with it the child would keep its whole EFFECTIVE set under the
	// service uid from the setuid until the execve (capabilities(7), "Effect of
	// user ID changes on capabilities"), able to open a root-only file; without
	// it the kernel clears the effective set at the setuid (KEEP_CAPS keeps the
	// permitted one), and the ambient set restores exactly the kept set at the
	// exec. The service cannot change its uid without CAP_SETUID, which is not
	// on the allowlist, so the fixup rules never apply to it.
	secbitsLocked = secbitNoRoot | secbitNoRootLocked
)
