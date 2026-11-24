// Command sdcreds reads and writes systemd credentials (the format of
// systemd-creds(1)) without systemd, and runs s6 services with decrypted
// credentials.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/go-authn/sdcreds"
	"github.com/go-authn/sdcreds/s6"
)

// osExit is replaced by the tests.
var osExit = os.Exit

// MachineIDEnv names a file read instead of /etc/machine-id. It holds no
// secret, only a path; systemd has no such variable.
const MachineIDEnv = s6.MachineIDEnv

func main() {
	cmd := RootCmd()
	if err := cmd.Execute(); err != nil {
		osExit(1)
	}
}

// RootCmd builds the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "sdcreds",
		Short:         "systemd credentials without systemd",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	root.AddCommand(encryptCmd(), decryptCmd(), setupCmd(), s6RunCmd(), s6FinishCmd())
	return root
}

func machineIDPath() string { return os.Getenv(MachineIDEnv) }

func hostKey() (sdcreds.HostKeyFile, error) {
	mid, err := sdcreds.ReadMachineID(machineIDPath())
	if err != nil {
		return sdcreds.HostKeyFile{}, err
	}
	return sdcreds.HostKeyFile{MachineID: mid}, nil
}

var tpmFlags = []string{"tpm2-device", "tpm2-pcrs", "tpm2-public-key", "tpm2-public-key-pcrs", "tpm2-signature", "tpm2-seal-key-handle"}

type keyFlags struct {
	withKey       string
	host          bool
	tpm           bool
	uid           string
	user          bool
	allowNull     bool
	refuseNull    bool
	name          string
	timestamp     string
	notAfter      string
	pretty        bool
	tpmFlagValues map[string]*string
}

func (k *keyFlags) register(cmd *cobra.Command, encrypt bool) {
	f := cmd.Flags()
	f.StringVar(&k.name, "name", "", "credential name (default: the file name; empty: none)")
	f.StringVar(&k.uid, "uid", "", "scope to this user (name or numeric id)")
	f.BoolVar(&k.user, "user", false, "scope to the calling user")
	f.BoolVar(&k.allowNull, "allow-null", false, "accept the null key")
	f.BoolVar(&k.refuseNull, "refuse-null", false, "refuse the null key")
	f.BoolVarP(&k.tpm, "tpm2", "T", false, "use the TPM2 (not supported)")
	k.tpmFlagValues = map[string]*string{}
	for _, n := range tpmFlags {
		v := new(string)
		k.tpmFlagValues[n] = v
		f.StringVar(v, n, "", "TPM2 option (not supported)")
		_ = f.MarkHidden(n)
	}
	if encrypt {
		f.StringVar(&k.withKey, "with-key", "auto", "key: null, host or auto (host)")
		f.BoolVarP(&k.host, "host", "H", false, "same as --with-key=host")
		f.StringVar(&k.timestamp, "timestamp", "", "credential timestamp: @SECONDS or RFC 3339")
		f.StringVar(&k.notAfter, "not-after", "", "credential expiry: @SECONDS or RFC 3339")
		f.BoolVarP(&k.pretty, "pretty", "p", false, "print a SetCredentialEncrypted= line")
	}
}

func (k *keyFlags) refuseTPM(cmd *cobra.Command) error {
	if k.tpm {
		return &sdcreds.UnsupportedModeError{Reason: "the TPM2 modes are not supported yet (--tpm2)"}
	}
	for _, n := range tpmFlags {
		if cmd.Flags().Changed(n) {
			return &sdcreds.UnsupportedModeError{Reason: "the TPM2 modes are not supported yet (--" + n + ")"}
		}
	}
	return nil
}

// scope resolves --uid/--user; nil when neither is given.
func (k *keyFlags) scope() (*sdcreds.Scope, error) {
	var u *user.User
	var err error
	switch {
	case k.user && k.uid != "":
		return nil, fmt.Errorf("%w: --user and --uid are exclusive", sdcreds.ErrInvalid)
	case k.user:
		u, err = user.Current()
	case k.uid != "":
		if _, nerr := strconv.ParseUint(k.uid, 10, 32); nerr == nil {
			u, err = user.LookupId(k.uid)
		} else {
			u, err = user.Lookup(k.uid)
		}
	default:
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return scopeOf(u)
}

// scopeOf is the scope of a user; the id must be a number (not a Windows SID).
func scopeOf(u *user.User) (*sdcreds.Scope, error) {
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, err
	}
	s := &sdcreds.Scope{UID: uint32(id), Username: u.Username}
	if p := machineIDPath(); p != "" {
		if s.MachineID, err = sdcreds.ReadMachineID(p); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// parseTime reads "@SECONDS" or RFC 3339 into microseconds.
func parseTime(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}
	var t time.Time
	if sec, ok := strings.CutPrefix(s, "@"); ok {
		n, err := strconv.ParseUint(sec, 10, 63)
		if err != nil || n > uint64(1<<62)/1_000_000 {
			return 0, fmt.Errorf("%w: bad time %q", sdcreds.ErrInvalid, s)
		}
		return n * 1_000_000, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil || t.UnixMicro() < 0 {
		return 0, fmt.Errorf("%w: bad time %q (want @SECONDS or RFC 3339)", sdcreds.ErrInvalid, s)
	}
	return uint64(t.UnixMicro()), nil
}

// credName is the name embedded or expected: --name when given, else the base
// name of path, none for stdin or stdout.
func credName(cmd *cobra.Command, explicit, path string) string {
	if cmd.Flags().Changed("name") {
		return explicit
	}
	if path == "" || path == "-" {
		return ""
	}
	return filepath.Base(path)
}

func argOr(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return "-"
}

func readInput(cmd *cobra.Command, path string, limit int64) ([]byte, error) {
	var r io.Reader = cmd.InOrStdin()
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: input exceeds %d bytes", sdcreds.ErrTooLarge, limit)
	}
	return b, nil
}

func writeOutput(cmd *cobra.Command, path string, data []byte) error {
	if path == "-" {
		_, err := cmd.OutOrStdout().Write(data)
		return err
	}
	return writeFileAtomic(path, data)
}

func encryptCmd() *cobra.Command {
	var k keyFlags
	cmd := &cobra.Command{
		Use:   "encrypt [INPUT|-] [OUTPUT|-]",
		Short: "encrypt a credential",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := k.refuseTPM(cmd); err != nil {
				return err
			}
			in, out := argOr(args, 0), argOr(args, 1)
			o := sdcreds.EncryptOptions{Name: credName(cmd, k.name, out), RefuseNull: k.refuseNull}
			if k.allowNull && k.refuseNull {
				return fmt.Errorf("%w: --allow-null and --refuse-null are exclusive", sdcreds.ErrInvalid)
			}
			switch {
			case k.host && cmd.Flags().Changed("with-key") && k.withKey != "host":
				return fmt.Errorf("%w: -H conflicts with --with-key=%s", sdcreds.ErrInvalid, k.withKey)
			case k.host:
				k.withKey = "host"
			}
			sc, err := k.scope()
			if err != nil {
				return err
			}
			switch k.withKey {
			case "null":
				o.Key = sdcreds.IDNull
			case "host", "auto":
				o.Key = sdcreds.IDHost
				if sc != nil {
					o.Key = sdcreds.IDHostScoped
					o.Scope = sc
				}
				hk, err := hostKey()
				if err != nil {
					return err
				}
				o.HostKey = hk
			default:
				return &sdcreds.UnsupportedModeError{Reason: fmt.Sprintf("--with-key=%s is not supported (null, host and auto are)", k.withKey)}
			}
			if o.Timestamp, err = parseTime(k.timestamp); err != nil {
				return err
			}
			if o.NotAfter, err = parseTime(k.notAfter); err != nil {
				return err
			}
			pt, err := readInput(cmd, in, sdcreds.PlaintextMax)
			if err != nil {
				return err
			}
			blob, err := sdcreds.Encrypt(pt, o)
			if err != nil {
				return err
			}
			if k.withKey == "null" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Credential will be secured with the null key, it offers no secrecy.")
			}
			if o.Name == "" {
				fmt.Fprintln(cmd.ErrOrStderr(), "Credential carries no name, so a service that requires one (s6-run) will refuse it; pass --name=NAME.")
			}
			if !k.pretty {
				return writeOutput(cmd, out, []byte(sdcreds.Armor(blob, sdcreds.ArmorWidth)))
			}
			// systemd-creds 262.2: without a name --pretty only narrows the lines.
			if o.Name == "" {
				return writeOutput(cmd, out, []byte(sdcreds.Armor(blob, sdcreds.ArmorWidthPretty)))
			}
			lines := strings.Split(strings.TrimSuffix(sdcreds.Armor(blob, sdcreds.ArmorWidthPretty), "\n"), "\n")
			var b strings.Builder
			fmt.Fprintf(&b, "SetCredentialEncrypted=%s: \\\n", o.Name)
			for i, l := range lines {
				b.WriteString("        " + l)
				if i < len(lines)-1 {
					b.WriteString(" \\")
				}
				b.WriteString("\n")
			}
			return writeOutput(cmd, out, []byte(b.String()))
		},
	}
	k.register(cmd, true)
	return cmd
}

func decryptCmd() *cobra.Command {
	var k keyFlags
	cmd := &cobra.Command{
		Use:   "decrypt [INPUT|-] [OUTPUT|-]",
		Short: "decrypt a credential",
		Args:  cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			hardenProcess()
			if err := k.refuseTPM(cmd); err != nil {
				return err
			}
			if k.allowNull && k.refuseNull {
				return fmt.Errorf("%w: --allow-null and --refuse-null are exclusive", sdcreds.ErrInvalid)
			}
			in, out := argOr(args, 0), argOr(args, 1)
			text, err := readInput(cmd, in, sdcreds.EncryptedMax*2)
			if err != nil {
				return err
			}
			sc, err := k.scope()
			if err != nil {
				return err
			}
			// A null-key credential needs no host key, so a machine id that
			// cannot be read is reported only if the credential asks for it.
			var hk sdcreds.HostKeySource
			if f, err := hostKey(); err != nil {
				hk = failingKey{err}
			} else {
				hk = f
			}
			name := credName(cmd, k.name, in)
			o := sdcreds.DecryptOptions{
				HostKey: hk, Scope: sc,
				AllowNull: k.allowNull, RefuseNull: k.refuseNull,
			}
			// No probe of the system admits a null-key credential: it is refused
			// on every machine unless --allow-null is given.
			// An empty name, as --name= gives, validates nothing.
			if name != "" {
				o.Name = &name
			}
			o.EnvOverrides()
			blob, err := sdcreds.Unarmor(text)
			if err != nil {
				return err
			}
			pt, _, err := sdcreds.Decrypt(blob, o)
			if err != nil {
				return err
			}
			return writeOutput(cmd, out, pt)
		},
	}
	k.register(cmd, false)
	return cmd
}

// createHostKey is replaced by the tests.
var createHostKey = sdcreds.CreateHostKey

func setupCmd() *cobra.Command {
	var path string
	cmd := &cobra.Command{
		Use:   "setup",
		Short: "create the host secret if it does not exist",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			mid, err := sdcreds.ReadMachineID(machineIDPath())
			if err != nil {
				return err
			}
			// An empty path is resolved by HostKey itself, which refuses a bad
			// $SYSTEMD_CREDENTIAL_SECRET; the lookup below cannot fail after it.
			_, err = sdcreds.HostKeyFile{Path: path, MachineID: mid}.HostKey()
			if path == "" && (err == nil || errors.Is(err, os.ErrNotExist)) {
				path, _ = sdcreds.HostSecretPath()
			}
			switch {
			case err == nil:
				fmt.Fprintf(cmd.OutOrStdout(), "host secret %s exists\n", path)
				return nil
			case !errors.Is(err, os.ErrNotExist):
				return err // present but unusable: never overwritten
			}
			if _, err := createHostKey(path, mid); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "host secret %s created\n", path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "host secret file (default $SYSTEMD_CREDENTIAL_SECRET or /var/lib/systemd/credential.secret)")
	return cmd
}

type s6Flags struct {
	service, user, baseDir, source string
	secret, machineIDFile          string
	unshare                        bool
	allowNull                      bool
	keepCap                        []string
}

// s6HostKey is the host key of the privileged s6-run path: the default files
// unless a flag names others, and a file named by a flag must be a regular file
// owned by root (trustedUID) that group and others cannot write. The
// environment plays no part. A file named by --secret is opened once: the
// descriptor that was judged is the one the key is read from, and the path is
// never opened again. wipe overwrites that key; call it when the credentials
// have been decrypted.
func s6HostKey(secret, machineID string) (key sdcreds.HostKeySource, wipe func(), err error) {
	wipe = func() {}
	var f *os.File
	if secret != "" {
		if f, err = openTrusted(secret); err != nil {
			return nil, wipe, fmt.Errorf("--secret: %w", err)
		}
		defer f.Close()
		afterSecretJudged(secret)
	}
	var mid [16]byte
	if machineID == "" {
		mid, err = sdcreds.ReadMachineID(sdcreds.MachineIDPath)
	} else {
		mid, err = readTrustedMachineID(machineID)
	}
	if err != nil {
		return nil, wipe, err
	}
	if f == nil {
		return sdcreds.HostKeyFile{Path: sdcreds.DefaultHostSecretPath, MachineID: mid}, wipe, nil
	}
	k, err := sdcreds.HostKeyFromFile(f, mid)
	if err != nil {
		return nil, wipe, fmt.Errorf("--secret: %w", err)
	}
	return sdcreds.StaticHostKey(k), func() { clear(k) }, nil
}

// afterSecretJudged runs once the --secret descriptor is judged and before it
// is read; a seam for the tests, which swap the path there.
var afterSecretJudged = func(string) {}

func (f *s6Flags) register(cmd *cobra.Command, run bool) {
	fl := cmd.Flags()
	fl.StringVar(&f.service, "service", "", "service name (the credential directory is BASE-DIR/SERVICE)")
	fl.StringVar(&f.baseDir, "base-dir", "/run/sdcreds", "absolute directory holding one directory per service (not /run/credentials: that one belongs to systemd)")
	_ = cmd.MarkFlagRequired("service")
	if run {
		fl.StringVar(&f.user, "user", "", "user that owns the credentials and runs the command")
		fl.StringVar(&f.source, "source", "", "directory of encrypted credentials, one file each")
		fl.StringVar(&f.secret, "secret", "", "host secret file to use instead of "+sdcreds.DefaultHostSecretPath+" (absolute, owned by root, not writable by group or others)")
		fl.StringVar(&f.machineIDFile, "machine-id-file", "", "machine id file to use instead of "+sdcreds.MachineIDPath+" (absolute, owned by root, not writable by group or others)")
		fl.BoolVar(&f.allowNull, "allow-null", false, "accept credentials sealed with the null key (no secrecy)")
		fl.BoolVar(&f.unshare, "unshare", true, "give this process a private mount namespace (the mount then dies with the service)")
		fl.StringArrayVar(&f.keepCap, "keep-cap", nil, "capability the command keeps (repeatable, or comma-separated); default none, so it runs with an empty capability set. "+
			"Allowlist only: CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_BROADCAST, CAP_IPC_LOCK, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND. "+
			"The kept set is the whole bounding, permitted, inheritable and ambient set of the command; no_new_privs stays on and the securebit NOROOT is locked. NET_ADMIN acts on the network namespace the command runs in, the host's unless it has one of its own")
		_ = cmd.MarkFlagRequired("user")
		_ = cmd.MarkFlagRequired("source")
	}
}

// s6Ops is replaced by the tests.
var s6Ops = s6.Real

// s6Run is replaced by the tests.
var s6Run = s6.Run

func s6RunCmd() *cobra.Command {
	var f s6Flags
	cmd := &cobra.Command{
		Use:   "s6-run --service S --user U --source DIR -- COMMAND [ARG...]",
		Short: "mount the decrypted credentials of a service and exec it",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// An unknown or forbidden capability stops the run here, before the key
			// is read, anything is decrypted or anything is mounted.
			keep, kerr0 := s6.ParseKeepCaps(f.keepCap)
			if kerr0 != nil {
				return kerr0
			}
			hardenProcess()
			// The key is never chosen by the environment: this runs with
			// privileges, in front of a service. SYSTEMD_CREDENTIAL_SECRET and
			// SDCREDS_MACHINE_ID_FILE are ignored; --secret and --machine-id-file
			// are the only overrides and name root-owned files.
			hk, wipe, kerr := s6HostKey(f.secret, f.machineIDFile)
			defer wipe()
			if kerr != nil {
				hk = failingKey{kerr}
			}
			c := s6.Config{
				Service: f.service, User: f.user, BaseDir: f.baseDir, Source: f.source,
				Unshare: f.unshare, KeepCaps: keep, Command: args, Env: os.Environ(),
				// The key is wiped as soon as decryption ends, before the
				// service starts; the defer above stays for an early return.
				Decrypted: wipe,
				Decrypt: func(name string, enc []byte) ([]byte, error) {
					blob, err := sdcreds.Unarmor(enc)
					if err != nil {
						return nil, err
					}
					// No EnvOverrides here: a service's environment must not steer
					// key material. A null or nameless credential is refused unless
					// the operator passed --allow-null.
					o := sdcreds.DecryptOptions{HostKey: hk, Name: &name, RequireName: true, AllowNull: f.allowNull}
					pt, _, err := sdcreds.Decrypt(blob, o)
					return pt, err
				},
			}
			// s6 supervises this process: its exit status is the service's.
			err := s6Run(c, s6Ops())
			var ee *s6.ExitError
			if errors.As(err, &ee) {
				osExit(ee.Code)
				return nil
			}
			return err
		},
	}
	f.register(cmd, true)
	return cmd
}

// failingKey defers the machine-id error until a credential needs the host key.
type failingKey struct{ err error }

func (k failingKey) HostKey() ([]byte, error) { return nil, k.err }

func s6FinishCmd() *cobra.Command {
	var f s6Flags
	cmd := &cobra.Command{
		Use:   "s6-finish --service S",
		Short: "release the credential directory of a service",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return s6.Finish(f.service, f.baseDir, s6Ops())
		},
	}
	f.register(cmd, false)
	return cmd
}
