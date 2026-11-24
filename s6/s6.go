// Package s6 runs a service with its credentials the way systemd does for
// LoadCredentialEncrypted=, for an s6 supervision tree: the credentials are
// decrypted into a per-service in-memory filesystem that is only readable by
// the service user and mounted read-only, the path goes into
// $CREDENTIALS_DIRECTORY, privileges are dropped and the service is executed.
// "s6-finish" releases the mount.
//
// The privileged system calls are the fields of Ops, so the logic here is
// portable and testable without root; the real implementation is Real() on
// Linux and a stub that reports ErrUnsupported elsewhere.
package s6

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/go-authn/sdcreds"
)

// Limits. A credential is at most sdcreds.PlaintextMax; a service gets 16 MiB
// of them at most, which also bounds the memory of an unbounded ramfs.
const (
	MaxTotal   = 16 << 20
	MaxEntries = 1024
	// EnvVar is the variable systemd sets (systemd.exec(5)).
	EnvVar = "CREDENTIALS_DIRECTORY"
	// MachineIDEnv is the variable of this package's tools that names the
	// machine-id file; it is not handed to the service.
	MachineIDEnv = "SDCREDS_MACHINE_ID_FILE"
)

// ErrUnsupported is returned by the stub Ops off Linux.
var ErrUnsupported = errors.New("s6: not supported on " + runtime.GOOS)

// ErrNotMounted is what Ops.Unmount returns when nothing was mounted there.
var ErrNotMounted = errors.New("s6: not a mount point")

// User is a resolved service account.
type User struct {
	UID, GID int
	Groups   []int
	// Keep is the allowlisted capabilities the service keeps (Config.KeepCaps);
	// Run sets it, Start applies it. Empty: the service has none.
	Keep []Cap
}

// Ops are the system calls that need privileges.
type Ops struct {
	LookupUser func(name string) (User, error)
	Unshare    func() error // new mount namespace, mounts private
	MountRAM   func(dir string) error
	Chown      func(path string, uid, gid int) error
	RemountRO  func(dir string) error
	Unmount    func(dir string) error // lazy; ErrNotMounted if not mounted
	// Start runs argv as u, in the mount namespace of the caller, and reports
	// whether the program was started: a failed exec (a file that is not a
	// program, a file system that forbids execution) is the error of Start itself.
	// The caller keeps its privileges, so it can still take the credentials away.
	// wait blocks until the program ends and returns its exit status (128 plus the
	// number of the signal that killed it).
	Start func(u User, argv []string, env []string) (wait func() (int, error), err error)
	// StartSignals, when set, is used instead of Start: the same, but the signals
	// to forward to the program are read from held, which Run holds from before
	// the first mount; the starter is their only reader from then on.
	StartSignals func(held <-chan os.Signal, u User, argv []string, env []string) (wait func() (int, error), err error)
	// Resolve finds the executable of argv[0]; optional. Run calls it before
	// anything is mounted.
	Resolve func(argv0 string) (string, error)
	// Move makes the mount at src appear at dst and detaches src.
	Move func(src, dst string) error
	// FSType names the file system at dir ("tmpfs", "ramfs", or anything else);
	// optional. Only a tmpfs or ramfs is ever unmounted.
	FSType func(dir string) (string, error)
	// CanExec reports whether the service user u may execute path (the result of
	// Resolve), judged by the kernel as that user. Optional. Run calls it before
	// anything is mounted: once the privileges are dropped a failed exec can no
	// longer take the credentials away.
	CanExec func(path string, u User) error
	// MountSource names the source (file-system name) of the mount on dir, and
	// whether dir is a mount point at all; optional. Run and Finish detach only
	// a mount whose source is MountTag, which is what this package mounts.
	MountSource func(dir string) (src string, mounted bool, err error)
}

// MountTag is the file-system name of every mount this package makes. It is
// the marker by which unmountAll recognises its own mounts.
const MountTag = "sdcreds"

// ErrForeignMount is returned when a memory file system at a credential
// directory was not made by this package.
var ErrForeignMount = errors.New("s6: refusing to unmount a mount that sdcreds did not create")

// requireDir refuses anything but a real directory at dir (a symlink is not
// followed).
func requireDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("s6: %s is not a directory (a symbolic link is not followed)", dir)
	}
	return nil
}

// Config describes one run.
type Config struct {
	Service string // credential directory name: a valid credential name
	User    string
	BaseDir string // absolute; the credentials live in BaseDir/Service
	Source  string // directory of encrypted credentials, one file each
	Unshare bool
	// KeepCaps are capabilities the service keeps (see ParseKeepCaps); each must be
	// on the allowlist, which Run checks before anything is decrypted or mounted.
	// None (the default): the service has an empty capability set.
	KeepCaps []Cap
	Command  []string
	Env      []string // the environment of the service, usually os.Environ()
	// Decrypt opens the encrypted file called name. It is where the key, the
	// name binding and the null-key policy are applied.
	Decrypt func(name string, encrypted []byte) ([]byte, error)
	// Decrypted, when set, is called once the credentials are decrypted (or
	// their decryption failed) and before anything is mounted or started: the
	// caller wipes the key there, so it does not stay in memory while the
	// service runs.
	Decrypted func()
}

func validate(service, base string) error {
	if !sdcreds.NameValid(service) {
		return fmt.Errorf("s6: invalid service name %q", service)
	}
	if !filepath.IsAbs(base) || filepath.Clean(base) != base {
		return fmt.Errorf("s6: base directory %q must be absolute and normalised", base)
	}
	return nil
}

// Dir is where the credentials of a service are mounted.
func Dir(base, service string) string { return filepath.Join(base, service) }

type entry struct {
	name string
	data []byte
}

func wipe(es []entry) {
	for _, e := range es {
		for i := range e.data {
			e.data[i] = 0
		}
	}
}

// load decrypts every credential of the source directory before anything is
// mounted, so a bad credential leaves nothing behind.
func load(c Config) ([]entry, error) {
	ents, err := os.ReadDir(c.Source)
	if err != nil {
		return nil, err
	}
	if len(ents) > MaxEntries {
		return nil, fmt.Errorf("s6: %s holds %d entries, at most %d", c.Source, len(ents), MaxEntries)
	}
	var out []entry
	total := 0
	for _, e := range ents {
		name := e.Name()
		if !sdcreds.NameValid(name) {
			wipe(out)
			return nil, fmt.Errorf("s6: %q is not a valid credential name", name)
		}
		raw, err := readLimited(filepath.Join(c.Source, name))
		if err != nil {
			wipe(out)
			return nil, err
		}
		pt, err := c.Decrypt(name, raw)
		if err != nil {
			wipe(out)
			return nil, fmt.Errorf("s6: credential %q: %w", name, err)
		}
		total += len(pt)
		out = append(out, entry{name, pt})
		if total > MaxTotal {
			wipe(out)
			return nil, fmt.Errorf("s6: credentials of %s exceed %d bytes: %w", c.Service, MaxTotal, sdcreds.ErrTooLarge)
		}
	}
	return out, nil
}

// readLimited reads a regular file (not a symlink) of bounded size. The file is
// opened once, without following a link or waiting on a pipe, and judged by
// what the descriptor says: nothing can be swapped between the check and the
// read.
func readLimited(path string) ([]byte, error) {
	f, err := openSource(path)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("s6: %s is not a regular file (a symbolic link is not followed)", path)
	}
	if err != nil {
		return nil, fmt.Errorf("s6: %s: %w", path, err)
	}
	defer f.Close()
	st, err := statFile(f)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("s6: %s is not a regular file", path)
	}
	b, err := readBounded(f)
	if err != nil {
		return nil, fmt.Errorf("s6: %s: %w", path, err)
	}
	return b, nil
}

// maxArmoured is the largest credential file read: the armoured form.
const maxArmoured = sdcreds.EncryptedMax*4/3 + 4096

// readBounded reads at most maxArmoured bytes and refuses a longer input.
func readBounded(r io.Reader) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxArmoured+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxArmoured {
		return nil, sdcreds.ErrTooLarge
	}
	return b, nil
}

// Seams for the tests: failures of these calls cannot be provoked on a real
// descriptor or inside a fresh private directory.
var (
	statFile  = func(f *os.File) (os.FileInfo, error) { return f.Stat() }
	mkdir     = os.Mkdir
	chmod     = os.Chmod
	mkdirTemp = os.MkdirTemp
)

// create makes a new file that must not exist; a variable for the tests.
var create = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
}

// Run prepares the credentials directory, runs the command as the service user
// in a child and waits for it, then undoes what it set up. It returns nil when
// the service exits 0, an *ExitError for another status, and an error when
// anything failed, the exec included.
func Run(c Config, ops Ops) (err error) {
	if err := validate(c.Service, c.BaseDir); err != nil {
		return err
	}
	if c.User == "" {
		return errors.New("s6: no service user")
	}
	if len(c.Command) == 0 {
		return errors.New("s6: no command")
	}
	if err := CheckKeepCaps(c.KeepCaps); err != nil {
		return err
	}
	u, err := ops.LookupUser(c.User)
	if err != nil {
		return fmt.Errorf("s6: user %q: %w", c.User, err)
	}
	u.Keep = c.KeepCaps
	// A command that cannot be found is learned before anything is mounted: after
	// the privileges are dropped nothing could take the credentials away again.
	path := c.Command[0]
	if ops.Resolve != nil {
		p, err := ops.Resolve(c.Command[0])
		if err != nil {
			return fmt.Errorf("s6: command %q: %w", c.Command[0], err)
		}
		path = p
	}
	// Root can run what the service user cannot: that is learned now, not by a
	// failed exec after the privileges are gone.
	if ops.CanExec != nil {
		if err := ops.CanExec(path, u); err != nil {
			return fmt.Errorf("s6: command %q cannot be executed by %s: %w", c.Command[0], c.User, err)
		}
	}
	creds, err := load(c)
	if c.Decrypted != nil {
		c.Decrypted()
	}
	if err != nil {
		return err
	}
	defer wipe(creds)
	// From here, before anything is staged or mounted, until the clean-up below
	// is over, a signal is not allowed to end this process: it would leave the
	// plaintext mounted. Registered before the clean-up, so released after it.
	// A signal that arrives before the service runs is acted on once everything
	// is taken away: Run then returns the status of a process killed by it.
	releaseSignals, caught, held := holdSignals()
	defer releaseSignals()
	interrupted := func() error {
		if sig := caught(); sig != 0 {
			return &ExitError{Code: 128 + sig}
		}
		return nil
	}

	// The mount namespace belongs to this thread; Start gives it to the thread
	// that starts the service.
	runtime.LockOSThread()
	if c.Unshare {
		if err := ops.Unshare(); err != nil {
			return fmt.Errorf("s6: unshare: %w", err)
		}
	}
	dir := Dir(c.BaseDir, c.Service)
	// The base directory is shared by every service and must stay traversable;
	// only the directory of this service is private.
	// A failure is judged by checkBase, which needs the directory to exist.
	// Whatever is created here gets its mode set explicitly: the umask of the
	// caller must not make the base unreadable to the service user.
	if err := makeBase(c.BaseDir); err != nil {
		return err
	}
	// Whoever can write to the base directory can swap what is mounted or
	// unmounted under it.
	if err := checkBase(c.BaseDir); err != nil {
		return err
	}
	// An existing directory is fine; requireDir judges whatever is there.
	_ = os.Mkdir(dir, 0o700)
	if err := requireDir(dir); err != nil {
		return err
	}
	if ops.Move == nil {
		return errors.New("s6: no way to move the staged mount into place")
	}
	// A mount left by an earlier run (or a stack of them) must not survive
	// under the new one.
	if err := unmountAll(ops, dir); err != nil {
		return fmt.Errorf("s6: %w", err)
	}
	// The credentials are written and frozen in a staging mount that sits under
	// a directory only root can enter, then moved to dir: until then no process
	// of the service user can reach them, let alone change them.
	stageRoot, err := mkdirTemp(c.BaseDir, stagePrefix(c.Service))
	if err != nil {
		return err
	}
	stage := filepath.Join(stageRoot, "mnt")
	staged, placed := false, false
	defer func() {
		// Every exit from here on cleans up, while this process still has its
		// privileges.
		var left error
		if staged {
			if uerr := unmountAll(ops, stage); uerr != nil {
				left = fmt.Errorf("credentials left mounted at %s: %w", stage, uerr)
			}
		}
		if placed {
			if uerr := unmountAll(ops, dir); uerr != nil {
				left = errors.Join(left, fmt.Errorf("credentials left mounted at %s: %w", dir, uerr))
			}
		}
		if left == nil {
			for _, p := range []string{stage, stageRoot, dir} {
				if rerr := os.Remove(p); rerr != nil && !errors.Is(rerr, os.ErrNotExist) {
					left = errors.Join(left, fmt.Errorf("could not remove %s: %w", p, rerr))
				}
			}
		}
		if left != nil && err == nil {
			err = left
		} else if left != nil {
			err = fmt.Errorf("%w; %w", err, left)
		}
	}()
	if err := mkdir(stage, 0o700); err != nil {
		return err
	}
	if err := interrupted(); err != nil {
		return err
	}
	if err := ops.MountRAM(stage); err != nil {
		return fmt.Errorf("s6: mount: %w", err)
	}
	staged = true
	if err := chmod(stage, 0o700); err != nil {
		return err
	}
	for _, e := range creds {
		p := filepath.Join(stage, e.name)
		f, err := create(p)
		if err != nil {
			return err
		}
		_, werr := f.Write(e.data)
		cerr := f.Close()
		if werr != nil || cerr != nil {
			return errors.Join(werr, cerr)
		}
		if err := ops.Chown(p, u.UID, u.GID); err != nil {
			return err
		}
	}
	// The plaintext is in the file system now and nowhere else is it needed: it
	// does not stay in this process for as long as the service runs.
	wipe(creds)
	if err := ops.Chown(stage, u.UID, u.GID); err != nil {
		return err
	}
	// Nothing writes into it any more: owner may read and enter, no more.
	if err := chmod(stage, 0o500); err != nil {
		return err
	}
	if err := ops.RemountRO(stage); err != nil {
		return fmt.Errorf("s6: remount read-only: %w", err)
	}
	if err := ops.Move(stage, dir); err != nil {
		return fmt.Errorf("s6: move mount into place: %w", err)
	}
	staged, placed = false, true
	for _, p := range []string{stage, stageRoot} {
		if err := os.Remove(p); err != nil {
			return fmt.Errorf("s6: %w", err)
		}
	}
	// The service gets the directory of its own credentials and nothing that
	// points at the key material of the host.
	env := slices.DeleteFunc(slices.Clone(c.Env), func(kv string) bool {
		for _, name := range []string{EnvVar, sdcreds.HostSecretEnv, MachineIDEnv} {
			if strings.HasPrefix(kv, name+"=") {
				return true
			}
		}
		return false
	})
	env = append(env, EnvVar+"="+dir)
	// This process keeps its privileges and its mount; the service runs in a
	// child that drops them. A failure to exec is reported by Start, so the
	// credentials are taken away below before Run fails.
	// A signal that came while the credentials were being staged stops the run
	// here: the service has not started, there is nothing to forward it to.
	if err := interrupted(); err != nil {
		return err
	}
	// While the service runs, Start forwards the signals to it; held as they
	// are, a second TERM during the clean-up cannot leave the mount behind.
	// The held signals are handed to the forwarder, which becomes their only
	// reader: one that came after the check above waits in the buffer and is
	// delivered once, one that comes later is delivered once when it arrives.
	startFn := ops.Start
	if ops.StartSignals != nil {
		startFn = func(u User, argv, env []string) (func() (int, error), error) {
			return ops.StartSignals(held, u, argv, env)
		}
	}
	wait, err := startFn(u, c.Command, env)
	if err != nil {
		return fmt.Errorf("s6: start %s: %w", c.Command[0], err)
	}
	code, err := wait()
	if err != nil {
		return fmt.Errorf("s6: waiting for %s: %w", c.Command[0], err)
	}
	if code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}

// ExitError is returned by Run when the service ran and ended with a non-zero
// status; the caller exits with Code.
type ExitError struct{ Code int }

func (e *ExitError) Error() string {
	return fmt.Sprintf("s6: the service exited with status %d", e.Code)
}

// makeBase creates base and any missing parent, and sets 0755 on each
// directory it created (by fchmod on the opened descriptor, so the umask and a
// swapped name do not matter). A directory that already exists is left as it
// is: checkBase judges it. A creation failure is not reported here either.
func makeBase(base string) error {
	var made []string
	for p := base; ; p = filepath.Dir(p) {
		if _, err := os.Lstat(p); err == nil {
			break
		}
		made = append(made, p)
	}
	_ = os.MkdirAll(base, 0o755)
	for _, p := range slices.Backward(made) {
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if err := fchmodDir(p, 0o755); err != nil {
			return fmt.Errorf("s6: %w", err)
		}
	}
	return nil
}

// maxLayers bounds the mounts stacked on one directory that unmountAll peels.
const maxLayers = 64

// unmountAll unmounts dir until nothing is mounted there: mounts stack, and a
// single unmount would uncover the layer below it.
func unmountAll(ops Ops, dir string) error {
	for i := 0; i < maxLayers; i++ {
		// Only a memory file system is ever detached: what else is mounted
		// there was not made by this package.
		if ops.FSType != nil {
			typ, err := ops.FSType(dir)
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if typ != "tmpfs" && typ != "ramfs" {
				return nil
			}
		}
		// Only what this package mounted is detached: a tmpfs that something
		// else mounted (or /run itself) is refused.
		if ops.MountSource != nil {
			src, mounted, err := ops.MountSource(dir)
			if err != nil {
				return err
			}
			if !mounted {
				return nil
			}
			if src != MountTag {
				return fmt.Errorf("%w: %s", ErrForeignMount, dir)
			}
		}
		err := ops.Unmount(dir)
		if errors.Is(err, ErrNotMounted) || errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return fmt.Errorf("%s is still mounted after %d unmounts", dir, maxLayers)
}

// stagePrefix starts the name of the staging directory of a service under the
// base: a fixed-length digest of the name, so that a service never sweeps the
// staging of another (a name cannot hold ':', a digest cannot be a prefix of a
// longer one, and a name of NameMax bytes still fits).
func stagePrefix(service string) string {
	sum := sha256.Sum256([]byte(service))
	return ".stage-" + hex.EncodeToString(sum[:8]) + "-"
}

// sweepStages takes away what a run of service left in its staging
// directories under base: the mount at <stage>/mnt, when this package made it,
// then the directory. A directory of another name, a symbolic link, and a mount
// that sdcreds did not make are left alone (the last is an error, as it is for
// the credential directory itself). It is idempotent.
func sweepStages(service, base string, ops Ops) error {
	ents, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("s6: %w", err)
	}
	prefix := stagePrefix(service)
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		root := filepath.Join(base, e.Name())
		if err := requireDir(root); err != nil {
			return err
		}
		mnt := filepath.Join(root, "mnt")
		if err := unmountAll(ops, mnt); err != nil {
			return fmt.Errorf("s6: unmount %s: %w", mnt, err)
		}
		for _, p := range []string{mnt, root} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("s6: %w", err)
			}
		}
	}
	return nil
}

// Finish releases the credentials of a service: the mount goes (lazily, so a
// process still holding a file keeps a private copy until it exits) and the
// empty directory is removed. It is idempotent.
func Finish(service, base string, ops Ops) error {
	if err := validate(service, base); err != nil {
		return err
	}
	dir := Dir(base, service)
	if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := checkBase(base); err != nil {
		return err
	}
	// A run that was ended while it staged leaves its staging mount behind.
	// A sweep that fails does not keep the live credential mount: it is taken
	// away below, and both errors are reported.
	sweepErr := sweepStages(service, base, ops)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return sweepErr
	}
	if err := requireDir(dir); err != nil {
		return errors.Join(sweepErr, err)
	}
	if err := unmountAll(ops, dir); err != nil {
		return errors.Join(sweepErr, fmt.Errorf("s6: unmount %s: %w", dir, err))
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(sweepErr, fmt.Errorf("s6: %w", err))
	}
	return sweepErr
}
