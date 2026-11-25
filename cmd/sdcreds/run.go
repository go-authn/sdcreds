package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/delivery"
	"github.com/go-authn/sdcreds/s6"
)

// Typed refusals of `sdcreds run`. Every one is returned, wrapped in a
// *refusal, before a key is opened, a secret decrypted or anything mounted.
var (
	errNoProgram     = errors.New("no PROGRAM after --")
	errProgramNotAbs = errors.New("PROGRAM must be an absolute, normalised path")
	errUnknownUser   = errors.New("unknown user")
	errBadClass      = errors.New("login class is not defined in login.conf")
	errKeepCapOS     = errors.New("--keep-cap exists on Linux only")
	errClassOS       = errors.New("--class exists on OpenBSD only")
	errNotExecutable = errors.New("PROGRAM cannot be executed by the target user")
	errMissingFlag   = errors.New("missing required flag")
)

// refusal is a validation failure: the exit status is 2.
type refusal struct{ err error }

func (r *refusal) Error() string { return "refused: " + r.err.Error() }
func (r *refusal) Unwrap() error { return r.err }

// exitRefused is the exit status of a refusal; 1 stays for other failures and
// the daemon's own status is passed through.
const exitRefused = 2

// Seams for the tests.
var (
	goos         = runtime.GOOS
	euid         = os.Geteuid
	lookupUser   = user.Lookup
	userGroupIDs = func(u *user.User) ([]string, error) { return u.GroupIds() }
	// runFlow is what runs once every refusal has passed; the platform files set it.
	runFlow func(cmd *cobra.Command, p *runPlan) error
)

// runFlags are the flags of `sdcreds run`.
type runFlags struct {
	service, user, source, class, base string
	secret, machineIDFile              string
	allowNull, check                   bool
	keepCap                            []string
}

// runPlan is the result of plan: everything the flow needs, judged.
type runPlan struct {
	runFlags
	program string
	args    []string // argv of the program after argv[0]
	uid     int
	gid     int
	groups  []int
	creds   []delivery.Credential
	keep    []s6.Cap
}

func defaultBase() string {
	if goos == "openbsd" {
		return delivery.DefaultBase
	}
	return "/run/sdcreds"
}

// plan runs every refusal of `run`, none of which needs the host key.
func plan(f runFlags, argv []string) (*runPlan, error) {
	p := &runPlan{runFlags: f}
	for _, m := range []struct{ name, v string }{{"--service", f.service}, {"--user", f.user}, {"--source", f.source}} {
		if m.v == "" {
			return nil, &refusal{fmt.Errorf("%w: %s", errMissingFlag, m.name)}
		}
	}
	if len(argv) == 0 {
		return nil, &refusal{errNoProgram}
	}
	if !filepath.IsAbs(argv[0]) || filepath.Clean(argv[0]) != argv[0] {
		return nil, &refusal{fmt.Errorf("%w: %q", errProgramNotAbs, argv[0])}
	}
	p.program, p.args = argv[0], argv[1:]
	if p.base == "" {
		p.base = defaultBase()
	}
	switch goos {
	case "openbsd":
		if len(f.keepCap) > 0 {
			return nil, &refusal{errKeepCapOS}
		}
	default:
		if f.class != "" {
			return nil, &refusal{errClassOS}
		}
		keep, err := s6.ParseKeepCaps(f.keepCap)
		if err != nil {
			return nil, &refusal{err}
		}
		p.keep = keep
	}
	if !delivery.ValidService(f.service) {
		return nil, &refusal{fmt.Errorf("%w: %q", delivery.ErrBadService, f.service)}
	}
	u, err := lookupUser(f.user)
	if err != nil {
		return nil, &refusal{fmt.Errorf("%w: %q", errUnknownUser, f.user)}
	}
	// The ids are read as the 32-bit numbers the kernel receives, before any
	// conversion: a text of 4294967296 must not become uid 0.
	uid, err1 := strconv.ParseUint(u.Uid, 10, 64)
	gid, err2 := strconv.ParseUint(u.Gid, 10, 64)
	if err1 != nil || err2 != nil {
		return nil, &refusal{fmt.Errorf("%w: %q has no numeric id", errUnknownUser, f.user)}
	}
	// Q9 and U10: uid 0, gid 0 and group 0 (wheel) are refused, whatever the
	// name; no flag lifts them.
	if err := delivery.ValidID(clampID(uid), "uid"); err != nil {
		return nil, &refusal{err}
	}
	if err := delivery.ValidID(clampID(gid), "gid"); err != nil {
		return nil, &refusal{err}
	}
	p.uid, p.gid = int(uid), int(gid)
	gids, err := userGroupIDs(u)
	if err != nil {
		return nil, &refusal{fmt.Errorf("groups of %q: %w", f.user, err)}
	}
	for _, g := range gids {
		n, err := strconv.ParseUint(g, 10, 64)
		if err != nil {
			return nil, &refusal{fmt.Errorf("%w: group %q of %q is not numeric", errUnknownUser, g, f.user)}
		}
		if err := delivery.ValidID(clampID(n), "group"); err != nil {
			return nil, &refusal{err}
		}
		p.groups = append(p.groups, int(n))
	}
	if goos == "openbsd" && f.class != "" {
		if err := checkClass(f.class); err != nil {
			return nil, &refusal{err}
		}
	}
	if euid() != 0 {
		return nil, &refusal{delivery.ErrNotRoot}
	}
	if err := canExecAs(p.program, p.uid, p.gid, p.groups); err != nil {
		return nil, &refusal{fmt.Errorf("%w: %v", errNotExecutable, err)}
	}
	creds, err := delivery.ReadSourceTrusted(f.source, trustedUID, ancestorsFrom)
	if err != nil {
		return nil, &refusal{err}
	}
	p.creds = creds
	// Sizes, names, duplicates: the same function Prepare runs first.
	if err := delivery.Check(delivery.Config{
		Base: p.base, Name: f.service, UID: p.uid, GID: p.gid, Creds: creds,
		Decrypt: func(string, []byte) ([]byte, error) { return nil, errors.New("not used") },
	}); err != nil {
		return nil, &refusal{err}
	}
	return p, nil
}

// clampID turns a parsed number into one ValidID can judge on any int size: a
// value above the 32-bit range is passed as the largest, which it refuses.
func clampID(n uint64) int64 {
	if n >= 0xFFFFFFFF {
		return 0xFFFFFFFF
	}
	return int64(n)
}

func checkClass(class string) error {
	var names []string
	f, err := os.Open(loginConfPath)
	if err == nil {
		names, err = ParseLoginClasses(f)
		f.Close()
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errBadClass, err)
	}
	for _, n := range names {
		if n == class {
			return nil
		}
	}
	return fmt.Errorf("%w: %q", errBadClass, class)
}

// decrypter is the Decrypt callback of a delivery: no environment steers the
// key, a nameless or null-key credential is refused unless --allow-null.
func decrypter(hk sdcreds.HostKeySource, allowNull bool) func(string, []byte) ([]byte, error) {
	return func(name string, enc []byte) ([]byte, error) {
		blob, err := sdcreds.Unarmor(enc)
		if err != nil {
			return nil, err
		}
		o := sdcreds.DecryptOptions{HostKey: hk, Name: &name, RequireName: true, AllowNull: allowNull}
		pt, _, err := sdcreds.Decrypt(blob, o)
		return pt, err
	}
}

func runCmd() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "run --service S --user U --source DIR [--class C] -- PROGRAM [ARG...]",
		Short: "deliver decrypted credentials to a program and run it",
		Long: "Decrypts the credentials of DIR (one sealed file each), makes them visible to PROGRAM\n" +
			"as $CREDENTIALS_DIRECTORY (read-only files owned by USER), runs PROGRAM as USER, and\n" +
			"removes them when it exits. USER must not be root. Every check runs before the key is\n" +
			"read; --check stops there.\n\n" +
			"On OpenBSD the files live in a locked memory file system. There is no mount namespace:\n" +
			"the mount is visible to every process and root can read the plaintext. Killing sdcreds\n" +
			"kills the program and unmounts. --class is checked against /etc/login.conf but its\n" +
			"limits are NOT applied to the program. On Linux this is s6-run with the same flags.",
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := plan(f, args)
			if err == nil && f.check {
				fmt.Fprintln(cmd.OutOrStdout(), "ok")
				return nil
			}
			if err == nil {
				if runFlow == nil {
					err = &refusal{delivery.ErrUnsupported}
				} else {
					err = runFlow(cmd, p)
				}
			}
			var r *refusal
			if errors.As(err, &r) {
				fmt.Fprintf(cmd.ErrOrStderr(), "sdcreds run: %v\n", r)
				osExit(exitRefused)
				return nil
			}
			return err
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&f.service, "service", "", "service name (lower case letters, digits, '_' and '-')")
	fl.StringVar(&f.user, "user", "", "user that owns the credentials and runs PROGRAM (never root)")
	fl.StringVar(&f.source, "source", "", "directory of encrypted credentials, one file each")
	fl.StringVar(&f.class, "class", "", "OpenBSD login class; validated against login.conf, limits not applied")
	fl.StringVar(&f.base, "base", "", "directory holding one credential directory per service (default "+delivery.DefaultBase+" on OpenBSD, /run/sdcreds on Linux)")
	fl.StringVar(&f.secret, "secret", "", "host key file (default /etc/sdcreds/host.key on OpenBSD, mode 0600; "+sdcreds.DefaultHostSecretPath+" on Linux)")
	fl.StringVar(&f.machineIDFile, "machine-id-file", "", "machine id file instead of sysctl hw.uuid (OpenBSD) or /etc/machine-id")
	fl.BoolVar(&f.allowNull, "allow-null", false, "accept credentials sealed with the null key (no secrecy)")
	fl.StringArrayVar(&f.keepCap, "keep-cap", nil, "Linux only: capability PROGRAM keeps (see s6-run)")
	fl.BoolVar(&f.check, "check", false, "run every refusal, decrypt nothing, start nothing")
	return cmd
}

// parseUUID reads the text of `sysctl hw.uuid`: 8-4-4-4-12 hex digits, not null.
func parseUUID(s string) ([16]byte, error) {
	var id [16]byte
	s = strings.TrimSuffix(s, "\n")
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, fmt.Errorf("%w: hw.uuid %q is not a UUID", sdcreds.ErrInvalid, s)
	}
	b, err := hex.DecodeString(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:])
	if err != nil {
		return id, fmt.Errorf("%w: hw.uuid: %v", sdcreds.ErrInvalid, err)
	}
	copy(id[:], b)
	if id == ([16]byte{}) {
		return id, fmt.Errorf("%w: hw.uuid is null", sdcreds.ErrInvalid)
	}
	return id, nil
}
