package delivery

import (
	"bufio"
	"compress/gzip"
	"embed"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:embed images/*.gz
var imageFS embed.FS

// mfsArgs mirrors struct mfs_args of OpenBSD (sys/mount.h, LP64: amd64 and
// arm64 agree, 144 bytes): the file-system name, an export_args that stays
// zero, and the memory the file system lives in.
type mfsArgs struct {
	fspec   *byte
	exFlags int32
	exRoot  uint32
	crUID   uint32
	crGID   uint32
	ngroups int16
	groups  [16]uint32
	exAddr  uintptr
	exAddrl int32
	exMask  uintptr
	exMaskl int32
	base    uintptr
	size    uintptr
}

const mfsArgsSize = 144

var tagBytes = append([]byte(MountTag), 0)

func newMfsArgs(region []byte) *mfsArgs {
	a := &mfsArgs{fspec: &tagBytes[0]}
	if len(region) > 0 {
		a.base = uintptr(unsafe.Pointer(&region[0]))
		a.size = uintptr(len(region))
	}
	return a
}

const mountFlags = unix.MNT_NOSUID | unix.MNT_NODEV | unix.MNT_NOEXEC | unix.MNT_NOATIME

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// isOurs reports whether st describes a mount made here.
func isOurs(st *unix.Statfs_t) bool {
	return cstr(st.F_fstypename[:]) == unix.MOUNT_MFS && cstr(st.F_mntfromname[:]) == MountTag
}

func loadImage(mib int, region []byte) error {
	f, err := imageFS.Open(fmt.Sprintf("images/ffs-%dMiB.gz", mib))
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	if _, err := io.ReadFull(zr, region); err != nil {
		return fmt.Errorf("delivery: image of %d MiB: %w", mib, err)
	}
	var one [1]byte
	if n, _ := zr.Read(one[:]); n != 0 {
		return fmt.Errorf("delivery: image of %d MiB is larger than its class", mib)
	}
	return nil
}

// raiseMemlock lifts the soft locked-memory limit to what the file system
// needs, within the hard limit.
func raiseMemlock(size int) error {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		return err
	}
	want := uint64(size) + 8<<20
	if rl.Cur >= want {
		return nil
	}
	if rl.Max < want {
		return fmt.Errorf("hard limit %d KiB is below the %d KiB needed", rl.Max>>10, want>>10)
	}
	rl.Cur = want
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl)
}

// HardenProcess keeps a core dump from carrying a secret.
func HardenProcess() { _ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{}) }

type ctlMsg struct {
	c   Ctl
	err error
}

// ServeMFS is the helper process: it owns the memory file system and the only
// copy of the locked region, and it never sees a secret except through the
// file system the owner writes. argv is --owner N --dir D --mib M; ctl is the
// control socket (descriptor 3 of the helper). It returns when the file system
// is gone.
func ServeMFS(argv []string, ctl *os.File) error {
	defer ctl.Close()
	say := func(c Ctl) { _, _ = ctl.Write([]byte(c.String() + "\n")) }
	fail := func(err error) error {
		say(Ctl{Kind: CtlFail, Text: err.Error()})
		return err
	}
	a, err := parseHelperArgs(argv)
	if err != nil {
		return fail(err)
	}
	HardenProcess()
	size := a.MiB << 20
	if err := raiseMemlock(size); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrMemLock, err))
	}
	region, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return fail(err)
	}
	defer clear(region)
	if err := unix.Mlock(region); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrMemLock, err))
	}
	if err := loadImage(a.MiB, region); err != nil {
		return fail(err)
	}

	// The owner watch is registered before the mount, so that no death is missed.
	kq, err := unix.Kqueue()
	if err != nil {
		return fail(err)
	}
	defer unix.Close(kq)
	ownerGone := make(chan struct{})
	ev := unix.Kevent_t{Ident: uint64(a.Owner), Filter: unix.EVFILT_PROC, Flags: unix.EV_ADD | unix.EV_ONESHOT, Fflags: unix.NOTE_EXIT}
	if _, err := unix.Kevent(kq, []unix.Kevent_t{ev}, nil, nil); err != nil {
		return fail(fmt.Errorf("delivery: owner %d: %w", a.Owner, err))
	}
	go func() {
		out := make([]unix.Kevent_t, 1)
		for {
			n, err := unix.Kevent(kq, nil, out, nil)
			if err == unix.EINTR {
				continue
			}
			if n > 0 || err != nil {
				close(ownerGone)
				return
			}
		}
	}()

	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM)
	signal.Ignore(syscall.SIGHUP, syscall.SIGINT, syscall.SIGPIPE)

	// mount(2) of an MFS does not return until the file system is unmounted: the
	// thread becomes the I/O server. It is a thread of its own, never given back.
	mountDone := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		mountDone <- unix.Mount(unix.MOUNT_MFS, a.Dir, mountFlags, unsafe.Pointer(newMfsArgs(region)))
	}()

	up := false
	for i := 0; i < 500 && !up; i++ {
		select {
		case err := <-mountDone:
			return fail(fmt.Errorf("%w: mount: %v", ErrMount, err))
		case <-ownerGone:
			return nil
		default:
		}
		var st unix.Statfs_t
		if unix.Statfs(a.Dir, &st) == nil && isOurs(&st) && cstr(st.F_mntonname[:]) == a.Dir {
			up = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !up {
		return fail(fmt.Errorf("%w: it did not appear", ErrMount))
	}

	msgs := make(chan ctlMsg)
	go func() {
		r := bufio.NewReaderSize(ctl, 512)
		for {
			c, err := readCtl(r)
			msgs <- ctlMsg{c, err}
			if err != nil {
				return
			}
		}
	}()
	say(Ctl{Kind: CtlReady})

	pgid := 0
	teardown := func(kill bool) {
		if kill && pgid >= 2 {
			_ = unix.Kill(-pgid, unix.SIGKILL)
		}
		_ = unix.Unmount(a.Dir, unix.MNT_FORCE)
		select {
		case <-mountDone:
		case <-time.After(5 * time.Second):
		}
	}
	for {
		select {
		case <-ownerGone:
			teardown(true)
			return nil
		case <-sigs:
			teardown(true)
			return nil
		case err := <-mountDone:
			// Unmounted from outside (Sweep, an operator): nothing is left to serve.
			_ = err
			return nil
		case m := <-msgs:
			if m.err != nil {
				// End of the socket or garbage: the owner is gone or confused.
				teardown(true)
				return nil
			}
			switch m.c.Kind {
			case CtlPGID:
				pgid = m.c.PGID
				say(Ctl{Kind: CtlOK})
			case CtlRelease:
				teardown(false)
				say(Ctl{Kind: CtlOK})
				return nil
			default:
				say(Ctl{Kind: CtlFail, Text: "unexpected message"})
			}
		}
	}
}
