//go:build linux

package s6

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"syscall"
)

// msNoSymFollow is MS_NOSYMFOLLOW (linux/mount.h), absent from package syscall.
const msNoSymFollow = 1 << 8

const hardening = syscall.MS_NODEV | syscall.MS_NOEXEC | syscall.MS_NOSUID | msNoSymFollow

// Real returns the Linux implementation; it needs root.
func Real() Ops {
	return Ops{
		LookupUser:     lookupUser,
		Unshare:        unshare,
		MountRAM:       mountRAM,
		Chown:          os.Lchown,
		RemountRO:      remountRO,
		Unmount:        unmount,
		DropPrivileges: dropPrivileges,
		Exec:           execve,
	}
}

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
	data := fmt.Sprintf("noswap,mode=0700,size=%d,nr_inodes=%d", MaxTotal+(1<<20), MaxEntries+16)
	err := syscall.Mount("tmpfs", dir, "tmpfs", hardening, data)
	if err == nil {
		return nil
	}
	if !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return syscall.Mount("ramfs", dir, "ramfs", hardening, "mode=0700")
}

func remountRO(dir string) error {
	return syscall.Mount("", dir, "", syscall.MS_REMOUNT|syscall.MS_RDONLY|hardening, "")
}

func unmount(dir string) error {
	err := syscall.Unmount(dir, syscall.MNT_DETACH)
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOENT) {
		return ErrNotMounted
	}
	return err
}

func dropPrivileges(u User) error {
	groups := u.Groups
	if len(groups) == 0 {
		groups = []int{u.GID}
	}
	if err := syscall.Setgroups(groups); err != nil {
		return err
	}
	if err := syscall.Setgid(u.GID); err != nil {
		return err
	}
	return syscall.Setuid(u.UID)
}

func execve(argv, env []string) error {
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, env)
}
