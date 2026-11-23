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

	"github.com/go-authn/sdcreds"
)

// Limits. A credential is at most sdcreds.PlaintextMax; a service gets 16 MiB
// of them at most, which also bounds the memory of an unbounded ramfs.
const (
	MaxTotal   = 16 << 20
	MaxEntries = 1024
	// EnvVar is the variable systemd sets (systemd.exec(5)).
	EnvVar = "CREDENTIALS_DIRECTORY"
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

// readLimited reads a regular file (not a symlink) of bounded size.
func readLimited(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("s6: %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
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
	creds, err := load(c)
	if err != nil {
		return err
	}
	defer wipe(creds)

	if c.Unshare {
		// The namespace belongs to this thread, and so does the exec.
		runtime.LockOSThread()
		if err := ops.Unshare(); err != nil {
			return fmt.Errorf("s6: unshare: %w", err)
		}
	}
	dir := Dir(c.BaseDir, c.Service)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	mounted := false
	defer func() {
		if err != nil {
			if mounted {
				_ = ops.Unmount(dir)
			}
			_ = os.Remove(dir)
		}
	}()
	if err := ops.MountRAM(dir); err != nil {
		return fmt.Errorf("s6: mount: %w", err)
	}
	mounted = true
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	for _, e := range creds {
		p := filepath.Join(dir, e.name)
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
	if err := ops.Chown(dir, u.UID, u.GID); err != nil {
		return err
	}
	if err := ops.RemountRO(dir); err != nil {
		return fmt.Errorf("s6: remount read-only: %w", err)
	}
	env := slices.DeleteFunc(slices.Clone(c.Env), func(kv string) bool { return strings.HasPrefix(kv, EnvVar+"=") })
	env = append(env, EnvVar+"="+dir)
	if err := ops.DropPrivileges(u); err != nil {
		return fmt.Errorf("s6: drop privileges: %w", err)
	}
	return fmt.Errorf("s6: exec %s: %w", c.Command[0], ops.Exec(c.Command, env))
}

// Finish releases the credentials of a service: the mount goes (lazily, so a
// process still holding a file keeps a private copy until it exits) and the
// empty directory is removed. It is idempotent.
func Finish(service, base string, ops Ops) error {
	if err := validate(service, base); err != nil {
		return err
	}
	dir := Dir(base, service)
	if err := ops.Unmount(dir); err != nil && !errors.Is(err, ErrNotMounted) && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("s6: unmount %s: %w", dir, err)
	}
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("s6: %w", err)
	}
	return nil
}
