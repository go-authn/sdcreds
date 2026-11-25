// Package delivery hands decrypted credentials to a service as a directory of
// read-only files, on OpenBSD, for a caller that starts the service itself
// (sdcreds run, or the exec-helper of a supervisor).
//
// The stated semantics (DESIGN.md, section 0):
//
//   - the consumer sees a directory Dir that holds one regular file per
//     credential, mode 0400, and is itself mode 0500, both owned by the target
//     user;
//   - the plaintext lives in memory only: in a locked memory file system, never
//     in a disk-backed file, argv, the environment or a URL;
//   - Dir lives from Prepare until Release is called, the owner process dies
//     (SIGKILL included), a Sweep runs, or the host reboots;
//   - every validation refuses before any secret is decrypted;
//   - the library never starts the consumer; it starts one helper process of its
//     own, through a hook the caller may replace (Config.SpawnHelper).
//
// OpenBSD has no mount namespace: the mount is visible host-wide and root can
// read the plaintext. See the package documentation of the README for what that
// does and does not protect.
//
// Off OpenBSD every function that needs the kernel returns ErrUnsupported; the
// validation, the control-protocol parser and the service lock are portable.
package delivery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
)

// Limits shared with the Linux path.
const (
	MaxTotal   = s6.MaxTotal
	MaxEntries = s6.MaxEntries
	// EnvVar is the variable systemd sets, which the consumer reads.
	EnvVar = s6.EnvVar
	// MountTag is the file-system name of every mount made here; Sweep and the
	// ownership checks recognise their own mounts by it.
	MountTag = s6.MountTag
	// DefaultBase is where the per-service directories live on OpenBSD.
	// /var/run is emptied by /etc/rc at boot.
	DefaultBase = "/var/run/sdcreds"
	// HelperCommand is argv[1] of the helper process the default SpawnHelper
	// starts: the program that embeds this package must call ServeMFS for it.
	HelperCommand = "__sdcreds-mfs"
	// maxDirLen is what the kernel keeps of the mount point: f_mntonname is
	// MNAMELEN (90) bytes with a final NUL. A longer path could not be recognised
	// by Sweep, so it is refused.
	maxDirLen = 89
	// maxGroups is NGROUPS_MAX of OpenBSD.
	maxGroups = 16
	// maxExeLen bounds the path of the executable on the helper's command line.
	maxExeLen = 1023
	// maxArmoured is the largest credential file accepted, the armoured form.
	maxArmoured = sdcreds.EncryptedMax*4/3 + 4096
	// maxSealedTotal bounds the sealed forms together: the plaintext cap in
	// base64 plus a generous header per entry.
	maxSealedTotal = MaxTotal*4/3 + MaxEntries*1024
)

// ErrUnsupported is returned where the delivery needs OpenBSD.
var ErrUnsupported = errors.New("delivery: not supported on " + runtime.GOOS)

// Typed refusals. Each is returned (wrapped) by Prepare before anything is
// decrypted, mounted or started, and each has a test.
var (
	ErrNotRoot       = errors.New("delivery: must run as root")
	ErrRootTarget    = errors.New("delivery: the target user must not be uid 0")
	ErrBadName       = errors.New("delivery: invalid name")
	ErrBadBase       = errors.New("delivery: invalid base directory")
	ErrTooManyEntry  = errors.New("delivery: too many credentials")
	ErrDuplicate     = errors.New("delivery: duplicate credential name")
	ErrNoDecrypt     = errors.New("delivery: no Decrypt function")
	ErrNoSuchHelper  = errors.New("delivery: no helper to start")
	ErrDirExists     = errors.New("delivery: the credential directory already exists (Release or Sweep it first)")
	ErrUntrustedPath = errors.New("delivery: untrusted path")
	ErrMount         = errors.New("delivery: the mount is not the one that was made")
	ErrMemLock       = errors.New("delivery: the memory could not be locked")
	ErrBusy          = errors.New("delivery: the service is already running (its lock is held)")
	ErrBadService    = errors.New("delivery: invalid service name")
)

// Credential is one sealed (armoured or raw) credential file and its name.
type Credential struct {
	Name   string
	Sealed []byte
}

// Config describes one delivery.
type Config struct {
	// Base is an absolute, normalised directory; the credentials appear in
	// Base/Name. Every ancestor must be owned by root and not writable by group
	// or others: mount follows symbolic links and OpenBSD has no way to forbid
	// it, so this check is the only defence.
	Base, Name string
	// UID and GID own the files. UID 0 is refused.
	UID, GID int
	// Groups are the supplementary groups of the target user; none may be 0.
	// The process that kills the target's processes runs with them.
	Groups []int
	Creds  []Credential
	// Decrypt opens one credential. It is where the key, the name binding and the
	// null-key policy are applied; it is called only after every other check has
	// passed. The returned plaintext is wiped by Prepare.
	Decrypt func(name string, sealed []byte) ([]byte, error)
	// SpawnHelper starts the helper process that serves the memory file system:
	// argv[0] is the command (HelperCommand); files[0] is its control socket and
	// files[1] the service lock, which the helper receives as descriptors 3 and 4
	// and keeps for as long as it lives, so that a second instance of the service
	// cannot start while a helper of the first one still holds a mount. nil:
	// execute Executable with argv, reaping the child. The caller of a custom
	// hook must make the helper run ServeMFS(argv[1:], files[0]). The helper never
	// gets a secret.
	SpawnHelper func(argv []string, files []*os.File) (pid int, err error)
	// Lock is the service lock the caller holds (AcquireLock); the helper
	// inherits it. Required.
	Lock *Lock
	// Executable is the program that embeds this package: an absolute, normalised
	// path that the caller has judged (root-owned, not writable by others, in
	// directories likewise). It runs the helper and the processes that kill the
	// target's processes; it is never taken from argv[0] or from PATH. Required.
	Executable string
}

// Further typed refusals.
var (
	ErrNoLock       = errors.New("delivery: no service lock: the helper must inherit the lock of the service")
	ErrNoExecutable = errors.New("delivery: no executable: an absolute path of the program that embeds this package is required")
)

// ErrBadID is a user or group id that is not a usable 32-bit value.
var ErrBadID = errors.New("delivery: invalid user or group id")

// ValidID refuses an id the target of a delivery may not have: 0 (root, or
// wheel), a negative number, anything that does not fit 32 bits, and
// 0xFFFFFFFF, which the kernel reads as "no change". It judges the number
// before any conversion to uint32, which is where 2^32 becomes 0.
func ValidID(n int64, what string) error {
	switch {
	case n == 0:
		return fmt.Errorf("%w: %s 0 (root) is refused", ErrRootTarget, what)
	case n < 0 || n >= 0xFFFFFFFF:
		return fmt.Errorf("%w: %s %d", ErrBadID, what, n)
	}
	return nil
}

// Dir is the directory that holds the credentials of a service.
func Dir(base, name string) string { return filepath.Join(base, name) }

// validate is every refusal that needs neither the system nor a secret. It is
// what makes "refuse before decrypting" (D4) a property of one function.
func validate(c Config, euid int) error {
	if euid != 0 {
		return ErrNotRoot
	}
	if !sdcreds.NameValid(c.Name) || strings.HasPrefix(c.Name, ".") {
		return fmt.Errorf("%w: service %q", ErrBadName, c.Name)
	}
	if !filepath.IsAbs(c.Base) || filepath.Clean(c.Base) != c.Base || c.Base == "/" {
		return fmt.Errorf("%w: %q must be absolute, normalised and not /", ErrBadBase, c.Base)
	}
	if n := len(Dir(c.Base, c.Name)); n > maxDirLen {
		return fmt.Errorf("%w: %q is %d bytes, at most %d (the kernel keeps %d of a mount point)", ErrBadBase, Dir(c.Base, c.Name), n, maxDirLen, maxDirLen)
	}
	// The ids are judged as the 32-bit values the kernel will receive: a value
	// that wraps to 0 is root, 0xFFFFFFFF is "no change" for chown.
	if err := ValidID(int64(c.UID), "uid"); err != nil {
		return err
	}
	if err := ValidID(int64(c.GID), "gid"); err != nil {
		return err
	}
	if len(c.Groups) > maxGroups {
		return fmt.Errorf("%w: %d supplementary groups, at most %d", ErrBadID, len(c.Groups), maxGroups)
	}
	for _, g := range c.Groups {
		if err := ValidID(int64(g), "group"); err != nil {
			return err
		}
	}
	if c.Decrypt == nil {
		return ErrNoDecrypt
	}
	if len(c.Creds) > MaxEntries {
		return fmt.Errorf("%w: %d, at most %d", ErrTooManyEntry, len(c.Creds), MaxEntries)
	}
	seen := make(map[string]bool, len(c.Creds))
	sealed := 0
	for _, cr := range c.Creds {
		if !sdcreds.NameValid(cr.Name) {
			return fmt.Errorf("%w: credential %q", ErrBadName, cr.Name)
		}
		if seen[cr.Name] {
			return fmt.Errorf("%w: %q", ErrDuplicate, cr.Name)
		}
		seen[cr.Name] = true
		if len(cr.Sealed) > maxArmoured {
			return fmt.Errorf("%w: credential %q is %d bytes", sdcreds.ErrTooLarge, cr.Name, len(cr.Sealed))
		}
		// The plaintext of a credential is shorter than its armoured form: when
		// the sealed forms alone are over the cap, the plaintext surely is too, and
		// that is learned before a key is touched.
		sealed += len(cr.Sealed)
		if sealed > maxSealedTotal {
			return fmt.Errorf("%w: the credentials of %s exceed the limit", sdcreds.ErrTooLarge, c.Name)
		}
	}
	return nil
}

// Check runs every refusal of Prepare that needs neither the system nor a
// secret, except ErrNotRoot (the caller tests its own uid), and changes
// nothing. A caller that wants to refuse before it reads a key (sdcreds run
// --check) calls it.
func Check(c Config) error { return validate(c, 0) }

// wipe overwrites the plaintext.
func wipe(bs [][]byte) {
	for _, b := range bs {
		clear(b)
	}
}

// decryptAll opens every credential; on any failure the plaintext so far is
// wiped. total is bounded by MaxTotal.
func decryptAll(c Config) ([][]byte, int, error) {
	var out [][]byte
	total := 0
	for _, cr := range c.Creds {
		pt, err := c.Decrypt(cr.Name, cr.Sealed)
		if err != nil {
			wipe(out)
			return nil, 0, fmt.Errorf("delivery: credential %q: %w", cr.Name, err)
		}
		out = append(out, pt)
		total += len(pt)
		if total > MaxTotal {
			wipe(out)
			return nil, 0, fmt.Errorf("delivery: credentials of %s exceed %d bytes: %w", c.Name, MaxTotal, sdcreds.ErrTooLarge)
		}
	}
	return out, total, nil
}

// Delivery is a prepared credential directory.
type Delivery struct {
	// Dir is the path the consumer reads, to put in $CREDENTIALS_DIRECTORY.
	Dir string

	impl *state // OpenBSD only
}

// geteuid is os.Geteuid; a variable so that a test can be root for Prepare.
var geteuid = os.Geteuid

// Prepare mounts the credentials of c at Dir and returns once they are in place,
// read-only. A failure, or a cancelled ctx, at any point after the helper was
// started runs Release.
func Prepare(ctx context.Context, c Config) (*Delivery, error) {
	if err := validate(c, geteuid()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Lock == nil {
		return nil, ErrNoLock
	}
	if !filepath.IsAbs(c.Executable) || filepath.Clean(c.Executable) != c.Executable {
		return nil, fmt.Errorf("%w: %q", ErrNoExecutable, c.Executable)
	}
	return prepare(ctx, c)
}

// Release zeroes and unmounts the directory and removes it. It is idempotent
// and safe to call after the helper died.
func (d *Delivery) Release() error {
	if d == nil {
		return nil
	}
	return d.release()
}

// GuardGroup arms the helper for the consumer that the caller started in the
// process group pgid (below 2 is refused). From then on, when this process dies
// or the mount is unmounted from outside, the helper sends SIGKILL to every
// process of the target user, however it left the group (setsid, setpgid,
// daemonizing), and only then unmounts: nothing may run without its owner. The
// group is not signalled itself, which would be wrong once its number is reused.
// The caller calls this before the consumer is allowed to exec.
func (d *Delivery) GuardGroup(pgid int) error {
	if d == nil {
		return errors.New("delivery: no delivery")
	}
	return d.guardGroup(pgid)
}

// Lost is closed when the helper has gone without Release having been called:
// the mount is then gone too (the kernel unmounts when the helper dies).
func (d *Delivery) Lost() <-chan struct{} {
	if d == nil || d.impl == nil {
		return nil
	}
	return d.impl.lost
}
