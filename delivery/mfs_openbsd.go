package delivery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	readyTimeout   = 15 * time.Second
	releaseTimeout = 5 * time.Second
)

type state struct {
	dir  string
	ctl  *os.File
	pid  int
	lost chan struct{}

	// what it takes to kill the processes of the target user
	exe      string
	uid, gid int
	groups   []int

	replies chan Ctl

	mu       sync.Mutex
	released bool
	done     chan struct{} // closed when the helper is reaped (default spawn)
}

// defaultSpawn starts exe, which Prepare has required to be an absolute path:
// the helper runs as root, so its program is never found through argv[0] or PATH.
func defaultSpawn(exe string) func(argv []string, files []*os.File) (int, error) {
	return func(argv []string, files []*os.File) (int, error) {
		cmd := exec.Command(exe, argv...)
		cmd.ExtraFiles = files
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Env = []string{}
		if err := cmd.Start(); err != nil {
			return 0, err
		}
		go func() { _ = cmd.Wait() }()
		return cmd.Process.Pid, nil
	}
}

func prepare(ctx context.Context, c Config) (d *Delivery, err error) {
	lockf, uidf := c.Lock.file(), c.UIDLock.file()
	if lockf == nil {
		return nil, ErrNoLock
	}
	if uidf == nil {
		return nil, ErrNoUIDLock
	}
	if err := EnsureBase(c.Base); err != nil {
		return nil, err
	}
	// The delivery kills every process of the target user when it ends: it must
	// own the user. One that has processes already is refused, before anything
	// is decrypted.
	// The release needs the killer user: without it nothing could be killed.
	// It must exist, must not be root or the target, and must own no process: a
	// release that cannot kill is refused here, before anything is delivered.
	killer, _, err := killerIDs(c.UID)
	if err != nil {
		return nil, err
	}
	if err := checkKillerAtStart(c.UID, killer, rootKillBudget, realProcs); err != nil {
		return nil, err
	}
	if busy, err := UIDBusy(c.UID); err != nil {
		return nil, err
	} else if busy {
		return nil, fmt.Errorf("%w: uid %d", ErrUIDBusy, c.UID)
	}
	pts, _, err := decryptAll(c)
	if err != nil {
		return nil, err
	}
	defer wipe(pts)
	names := make([]string, len(c.Creds))
	sizes := make([]int, len(c.Creds))
	for i, cr := range c.Creds {
		names[i], sizes[i] = cr.Name, len(pts[i])
	}
	cl, err := pickClass(names, sizes)
	if err != nil {
		return nil, err
	}
	dir := Dir(c.Base, c.Name)
	if err := unix.Mkdir(dir, 0o700); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return nil, fmt.Errorf("%w: %s", ErrDirExists, dir)
		}
		return nil, &os.PathError{Op: "mkdir", Path: dir, Err: err}
	}
	st := &state{dir: dir, lost: make(chan struct{}), replies: make(chan Ctl, 8),
		exe: c.Executable, uid: c.UID, gid: c.GID, groups: c.Groups}
	made := &Delivery{Dir: dir, impl: st}
	d = made
	// d is the result variable: a "return nil, err" has already cleared it when
	// this runs, so the release goes through made.
	defer func() {
		if err != nil {
			if rerr := made.Release(); rerr != nil {
				err = errors.Join(err, rerr)
			}
		}
	}()

	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	mine, theirs := os.NewFile(uintptr(fds[0]), "ctl"), os.NewFile(uintptr(fds[1]), "ctl-helper")
	st.ctl = mine
	spawn := c.SpawnHelper
	if spawn == nil {
		spawn = defaultSpawn(c.Executable)
	}
	args := helperArgs{Owner: os.Getpid(), Dir: dir, MiB: cl.MiB, UID: c.UID, GID: c.GID, Groups: c.Groups, Exe: c.Executable}
	pid, err := spawn(append([]string{HelperCommand}, args.argv()...), []*os.File{theirs, lockf, uidf})
	theirs.Close()
	if err != nil {
		return nil, fmt.Errorf("delivery: starting the helper: %w", err)
	}
	st.pid = pid
	go st.readReplies()

	if err := st.expect(ctx, CtlReady, readyTimeout); err != nil {
		return nil, err
	}

	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(dfd)
	if err := verifyMount(dfd, false); err != nil {
		return nil, err
	}
	if err := verifyEmpty(dfd); err != nil {
		return nil, err
	}
	if err := unix.Fchmod(dfd, 0o700); err != nil {
		return nil, err
	}
	for i, cr := range c.Creds {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writeOne(dfd, cr.Name, pts[i], c.UID, c.GID); err != nil {
			return nil, err
		}
	}
	if err := unix.Fchown(dfd, c.UID, c.GID); err != nil {
		return nil, err
	}
	if err := unix.Fchmod(dfd, 0o500); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := unix.Mount(unix.MOUNT_MFS, dir, mountFlags|unix.MNT_UPDATE|unix.MNT_RDONLY, unsafe.Pointer(newMfsArgs(nil))); err != nil {
		return nil, fmt.Errorf("delivery: remounting %s read-only: %w", dir, err)
	}
	if err := verifyMount(dfd, true); err != nil {
		return nil, err
	}
	return d, nil
}

// verifyMount checks, on the descriptor opened on the directory, that what is
// there is the memory file system made here (and read-only when asked).
func verifyMount(fd int, rdonly bool) error {
	var sf unix.Statfs_t
	if err := unix.Fstatfs(fd, &sf); err != nil {
		return err
	}
	if !isOurs(&sf) {
		return fmt.Errorf("%w: %q on %q", ErrMount, cstr(sf.F_mntfromname[:]), cstr(sf.F_mntonname[:]))
	}
	if sf.F_flags&(unix.MNT_NOSUID|unix.MNT_NODEV|unix.MNT_NOEXEC) != unix.MNT_NOSUID|unix.MNT_NODEV|unix.MNT_NOEXEC {
		return fmt.Errorf("%w: the mount lacks nosuid, nodev or noexec", ErrMount)
	}
	if rdonly && sf.F_flags&unix.MNT_RDONLY == 0 {
		return fmt.Errorf("%w: the mount is not read-only", ErrMount)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if st.Ino != 2 {
		return fmt.Errorf("%w: the directory is not the root of a file system", ErrMount)
	}
	return nil
}

// verifyEmpty refuses a root that holds anything: the image is empty, and a file
// already there was not put there by this process.
func verifyEmpty(fd int) error {
	nfd, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(nfd), "root")
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return err
	}
	if len(names) != 0 {
		return fmt.Errorf("%w: the new file system is not empty (%d entries)", ErrMount, len(names))
	}
	return nil
}

func writeOne(dfd int, name string, pt []byte, uid, gid int) error {
	fd, err := unix.Openat(dfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o400)
	if err != nil {
		return &os.PathError{Op: "create", Path: name, Err: err}
	}
	defer unix.Close(fd)
	for off := 0; off < len(pt); {
		n, err := unix.Write(fd, pt[off:])
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return &os.PathError{Op: "write", Path: name, Err: err}
		}
		off += n
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return err
	}
	return unix.Fchmod(fd, 0o400)
}

func (s *state) readReplies() {
	r := bufio.NewReaderSize(s.ctl, 512)
	for {
		c, err := readCtl(r)
		if err != nil {
			s.mu.Lock()
			rel := s.released
			s.mu.Unlock()
			close(s.replies)
			if !rel {
				close(s.lost)
			}
			return
		}
		s.replies <- c
	}
}

func (s *state) expect(ctx context.Context, want CtlKind, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case c, ok := <-s.replies:
		if !ok {
			return errors.New("delivery: the helper ended without answering")
		}
		if c.Kind == CtlFail {
			if strings.Contains(c.Text, ErrMemLock.Error()) {
				return fmt.Errorf("%w: %s", ErrMemLock, c.Text)
			}
			return fmt.Errorf("delivery: the helper failed: %s", c.Text)
		}
		if c.Kind != want {
			return fmt.Errorf("delivery: the helper said %q, wanted %q", c.String(), Ctl{Kind: want}.String())
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return errors.New("delivery: the helper did not answer in time")
	}
}

func (d *Delivery) guardGroup(pgid int) error {
	if pgid < 2 {
		return fmt.Errorf("%w: process group %d", ErrBadName, pgid)
	}
	s := d.impl
	if s == nil {
		return errors.New("delivery: not prepared")
	}
	if _, err := s.ctl.Write([]byte(Ctl{Kind: CtlPGID, PGID: pgid}.String() + "\n")); err != nil {
		return err
	}
	return s.expect(context.Background(), CtlOK, releaseTimeout)
}

func (d *Delivery) release() error {
	s := d.impl
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if s.released {
		s.mu.Unlock()
		return nil
	}
	s.released = true
	s.mu.Unlock()
	var kerr error
	if s.ctl != nil {
		_, _ = s.ctl.Write([]byte(Ctl{Kind: CtlRelease}.String() + "\n"))
		// Earlier messages (a "ready" nobody read, for one) come before the answer.
		// The helper kills the target's processes before it answers.
		t := time.NewTimer(releaseTimeout + killTotal)
		answered := false
	wait:
		for {
			select {
			case c, ok := <-s.replies:
				if !ok {
					break wait
				}
				if c.Kind == CtlFail {
					kerr = errors.New(c.Text)
				}
				if c.Kind == CtlOK || c.Kind == CtlFail {
					answered = true
					break wait
				}
			case <-t.C:
				break wait
			}
		}
		t.Stop()
		_ = s.ctl.Close()
		// A helper that is gone cannot have killed anything: this process does.
		if !answered {
			kerr = errors.Join(kerr, s.killTarget())
		}
	}
	return errors.Join(kerr, removeMount(s.dir))
}

func (s *state) killTarget() error { return KillUID(s.exe, s.uid, s.gid, s.groups) }

// VerifyOnlyProcess is ErrUIDBusy unless pid is the only process of the target
// user. The caller makes it after it has guarded the program and before it lets
// it run: anything else that appeared under the user in between is refused.
func (d *Delivery) VerifyOnlyProcess(pid int) error {
	if d == nil || d.impl == nil {
		return errors.New("delivery: no delivery")
	}
	return VerifyOnlyProcess(d.impl.uid, pid)
}

// KillTarget sends SIGKILL to every process of the target user, from this
// process; the caller uses it when the helper is gone (Lost is closed).
func (d *Delivery) KillTarget() error {
	if d == nil || d.impl == nil {
		return errors.New("delivery: no delivery")
	}
	return d.impl.killTarget()
}

// unmountTimeout bounds a forced unmount: an MFS is unmounted by its helper
// process, and one that cannot run (stopped, wedged) would hold the caller for
// ever. A variable for the tests.
var unmountTimeout = 10 * time.Second

// ErrWedged is returned when a forced unmount does not finish in time.
var ErrWedged = errors.New("delivery: the unmount did not finish; the helper of the mount is not running")

func forceUnmount(dir string) error {
	res := make(chan error, 1)
	go func() { res <- unix.Unmount(dir, unix.MNT_FORCE) }()
	select {
	case err := <-res:
		return err
	case <-time.After(unmountTimeout):
		return fmt.Errorf("%w: %s", ErrWedged, dir)
	}
}

// removeMount makes sure nothing is mounted at dir and removes it.
func removeMount(dir string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err == nil && isOurs(&st) && cstr(st.F_mntonname[:]) == dir {
		if err := forceUnmount(dir); err != nil && !errors.Is(err, unix.ENOENT) {
			return &os.PathError{Op: "unmount", Path: dir, Err: err}
		}
	}
	if err := unix.Rmdir(dir); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "rmdir", Path: dir, Err: err}
	}
	return nil
}

// Swept is one leftover that Sweep removed.
type Swept struct {
	Dir     string
	Mounted bool
}

// Sweep removes what a crashed owner and helper left under base: every mount
// made here (recognised by its tag) is force-unmounted, and every empty
// directory of a service removed. Dot files (locks) are left alone.
func Sweep(base string) ([]Swept, error) { return sweep(base, "") }

// SweepService is Sweep for one service.
func SweepService(base, service string) ([]Swept, error) {
	if !ValidService(service) {
		return nil, fmt.Errorf("%w: %q", ErrBadService, service)
	}
	return sweep(base, service)
}

func sweep(base, service string) ([]Swept, error) {
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return nil, fmt.Errorf("%w: %q", ErrBadBase, base)
	}
	n, err := unix.Getfsstat(nil, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	buf := make([]unix.Statfs_t, n+8)
	n, err = unix.Getfsstat(buf, unix.MNT_NOWAIT)
	if err != nil {
		return nil, err
	}
	var out []Swept
	for i := 0; i < n && i < len(buf); i++ {
		if !isOurs(&buf[i]) {
			continue
		}
		on := cstr(buf[i].F_mntonname[:])
		if filepath.Dir(on) != base || (service != "" && filepath.Base(on) != service) {
			continue
		}
		if err := forceUnmount(on); err != nil {
			return out, &os.PathError{Op: "unmount", Path: on, Err: err}
		}
		_ = unix.Rmdir(on)
		out = append(out, Swept{on, true})
	}
	ents, err := os.ReadDir(base)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return out, err
	}
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") || !e.IsDir() || (service != "" && name != service) {
			continue
		}
		p := filepath.Join(base, name)
		if unix.Rmdir(p) == nil {
			out = append(out, Swept{p, false})
		}
	}
	return out, nil
}
