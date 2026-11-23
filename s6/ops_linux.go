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
	"strconv"
	"syscall"
	"unsafe"
)

// msNoSymFollow is MS_NOSYMFOLLOW (linux/mount.h), absent from package syscall.
const msNoSymFollow = 1 << 8

const hardening = syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID | msNoSymFollow

// Real returns the Linux implementation; it needs root.
func Real() Ops {
	return Ops{
		LookupUser:  lookupUser,
		Unshare:     unshare,
		MountRAM:    mountRAM,
		Chown:       os.Lchown,
		RemountRO:   remountRO,
		Unmount:     unmount,
		Start:       start,
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
	u, err := user.Lookup(name)
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
	ids, err := u.GroupIds()
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
	if err := syscall.Unshare(syscall.CLONE_NEWNS); err != nil {
		return err
	}
	return syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, "")
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
	err = syscall.Mount(MountTag, target, "tmpfs", hardening, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return syscall.Mount(MountTag, target, "ramfs", hardening, "mode=0700")
}

const threadMountinfo = "/proc/thread-self/mountinfo"

// mountSource reads the mount table of the calling thread for dir. Not
// /proc/self/mountinfo: that is the table of the thread-group leader, and Run
// unshares the mount namespace of its own (locked) thread only.
func mountSource(dir string) (string, bool, error) {
	real, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return "", false, err
	}
	table, err := os.ReadFile(threadMountinfo)
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
	prev, err := syscall.Getgroups()
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
	if _, _, e := syscall.RawSyscall(trap, uintptr(id), uintptr(id), uintptr(saved)); e != 0 {
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
	if _, _, e := syscall.RawSyscall(trapSetgroups, uintptr(len(ids)), uintptr(p), 0); e != 0 {
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
		aerr = syscall.Access(path, 1) // X_OK, by the real id, which is u's now
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
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	return nil
}

func remountRO(dir string) error {
	target, release, err := pin(dir)
	if err != nil {
		return err
	}
	defer release()
	return syscall.Mount("", target, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|hardening, "")
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
		return "", nil, &os.PathError{Op: "open", Path: dir, Err: err}
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
	if err := syscall.Mount(s, d, "", syscall.MS_BIND, ""); err != nil {
		return err
	}
	return unmount(src)
}

// umountNoFollow is UMOUNT_NOFOLLOW (sys/mount.h): never follow a final symlink.
const umountNoFollow = 0x8

func unmount(dir string) error {
	err := syscall.Unmount(dir, syscall.MNT_DETACH|umountNoFollow)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
		return ErrNotMounted
	}
	return err
}

// fsType names the file system at dir, by the magic numbers of statfs(2).
func fsType(dir string) (string, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
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
	capLastCapMax   = 63
)

func prctl(option, arg2 uintptr) (uintptr, error) {
	r, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, option, arg2, 0, 0, 0, 0)
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
func restrictThread() error {
	if _, err := prctl(prSetNoNewPrivs, 1); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	for c := uintptr(0); c <= capLastCapMax; c++ {
		if _, err := prctl(prCapbsetRead, c); err != nil {
			if errors.Is(err, syscall.EINVAL) {
				break // past the last capability of this kernel
			}
			return fmt.Errorf("capability bounding set: %w", err)
		}
		if _, err := prctl(prCapbsetDrop, c); err != nil {
			return fmt.Errorf("capability bounding set: %w", err)
		}
	}
	return nil
}
