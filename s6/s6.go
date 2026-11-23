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
}

// Ops are the system calls that need privileges.
type Ops struct {
	LookupUser     func(name string) (User, error)
	Unshare        func() error // new mount namespace, mounts private
	MountRAM       func(dir string) error
	Chown          func(path string, uid, gid int) error
	RemountRO      func(dir string) error
	Unmount        func(dir string) error // lazy; ErrNotMounted if not mounted
	DropPrivileges func(u User) error
	Exec           func(argv []string, env []string) error
	// Resolve finds the executable of argv[0]; optional. Run calls it before
	// anything is mounted.
	Resolve func(argv0 string) (string, error)
	// Move makes the mount at src appear at dst and detaches src.
	Move func(src, dst string) error
	// FSType names the file system at dir ("tmpfs", "ramfs", or anything else);
	// optional. Only a tmpfs or ramfs is ever unmounted.
	FSType func(dir string) (string, error)
}

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
	Command []string
	Env     []string // the environment of the service, usually os.Environ()
	// Decrypt opens the encrypted file called name. It is where the key, the
	// name binding and the null-key policy are applied.
	Decrypt func(name string, encrypted []byte) ([]byte, error)
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
	st, err := f.Stat()
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

// create makes a new file that must not exist; a variable for the tests.
var create = func(path string) (io.WriteCloser, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o400)
}

// Run prepares the credentials directory and executes the command. It returns
// only on failure, after undoing what it set up.
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
	u, err := ops.LookupUser(c.User)
	if err != nil {
		return fmt.Errorf("s6: user %q: %w", c.User, err)
	}
	// A command that cannot be found is learned before anything is mounted: after
	// the privileges are dropped nothing could take the credentials away again.
	if ops.Resolve != nil {
		if _, err := ops.Resolve(c.Command[0]); err != nil {
			return fmt.Errorf("s6: command %q: %w", c.Command[0], err)
		}
	}
	creds, err := load(c)
	if err != nil {
		return err
	}
	defer wipe(creds)

	// The thread-bound state (mount namespace, bounding set, no_new_privs) is
	// inherited by the exec, which therefore runs on this thread.
	runtime.LockOSThread()
	if c.Unshare {
		if err := ops.Unshare(); err != nil {
			return fmt.Errorf("s6: unshare: %w", err)
		}
	}
	dir := Dir(c.BaseDir, c.Service)
	// The base directory is shared by every service and must stay traversable;
	// only the directory of this service is private.
	if err := os.MkdirAll(c.BaseDir, 0o755); err != nil {
		return err
	}
	// Whoever can write to the base directory can swap what is mounted or
	// unmounted under it.
	if err := checkBase(c.BaseDir); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
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
	stageRoot, err := os.MkdirTemp(c.BaseDir, ".stage-")
	if err != nil {
		return err
	}
	stage := filepath.Join(stageRoot, "mnt")
	staged, placed := false, false
	defer func() {
		// Run never returns nil from here on (a failed exec is an error
		// too), so every exit cleans up.
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
		if left != nil {
			err = fmt.Errorf("%w; %w", err, left)
		}
	}()
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	if err := ops.MountRAM(stage); err != nil {
		return fmt.Errorf("s6: mount: %w", err)
	}
	staged = true
	if err := os.Chmod(stage, 0o700); err != nil {
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
	if err := ops.Chown(stage, u.UID, u.GID); err != nil {
		return err
	}
	// Nothing writes into it any more: owner may read and enter, no more.
	if err := os.Chmod(stage, 0o500); err != nil {
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
	if err := ops.DropPrivileges(u); err != nil {
		return fmt.Errorf("s6: drop privileges: %w", err)
	}
	return fmt.Errorf("s6: exec %s: %w", c.Command[0], ops.Exec(c.Command, env))
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
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := requireDir(dir); err != nil {
		return err
	}
	if err := unmountAll(ops, dir); err != nil {
		return fmt.Errorf("s6: unmount %s: %w", dir, err)
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("s6: %w", err)
	}
	return nil
}
