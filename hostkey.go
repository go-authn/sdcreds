package sdcreds

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// HostKeySource supplies the host secret that is mixed into the encryption key
// for the host and host-scoped types.
type HostKeySource interface {
	HostKey() ([]byte, error)
}

// StaticHostKey is a host secret held in memory (the bytes after the 16-byte
// machine-id prefix of the file, cu.c:638).
type StaticHostKey []byte

// HostKey implements HostKeySource.
func (k StaticHostKey) HostKey() ([]byte, error) { return []byte(k), nil }

const (
	// DefaultHostSecretPath is where systemd keeps the host secret (cu.c:544-545).
	DefaultHostSecretPath = "/var/lib/systemd/credential.secret"
	// HostSecretEnv names the environment variable that overrides the path (cu.c:527).
	HostSecretEnv = "SYSTEMD_CREDENTIAL_SECRET"
	// HostSecretDataSize is the random part of a generated host secret (cu.c:417).
	HostSecretDataSize = 4096
	// MachineIDPath is the machine id file read by sd_id128_get_machine.
	MachineIDPath = "/etc/machine-id"
)

// machineIDFile is where ReadMachineID("") reads; a variable for the tests.
var machineIDFile = MachineIDPath

// credentialAppID is credential_app_id (cu.c:419-420).
var credentialAppID = [16]byte{0xd3, 0xac, 0xec, 0xba, 0x0d, 0xad, 0x4c, 0xdf, 0xb8, 0xc9, 0x38, 0x15, 0x28, 0x93, 0x6c, 0x58}

// ErrHostKeyMachine is a host secret file that belongs to another machine id.
// systemd deletes such a file when it may generate a new one (cu.c:656-677);
// this library only refuses it.
var ErrHostKeyMachine = errors.New("sdcreds: host secret comes from a different machine id")

// AppSpecificID is sd_id128_get_app_specific (sd-id128.c:340-355):
// HMAC-SHA256(key = machine id, message = app id), first 16 bytes, stamped as
// a version-4 DCE UUID (id128-util.c:211-222).
func AppSpecificID(machineID, appID [16]byte) [16]byte {
	mac := hmac.New(sha256.New, machineID[:])
	mac.Write(appID[:])
	var out [16]byte
	copy(out[:], mac.Sum(nil))
	out[6] = out[6]&0x0f | 0x40
	out[8] = out[8]&0x3f | 0x80
	return out
}

// HostSecretMachineID is the 16-byte prefix a host secret file must carry for
// machineID (cu.c:523).
func HostSecretMachineID(machineID [16]byte) [16]byte {
	return AppSpecificID(machineID, credentialAppID)
}

// ParseMachineID parses the content of a machine-id file: 32 hex digits, an
// optional newline, and not all zero.
func ParseMachineID(b []byte) ([16]byte, error) {
	var id [16]byte
	s := strings.TrimSuffix(string(b), "\n")
	if len(s) != 32 {
		return id, fmt.Errorf("%w: machine id must be 32 hex digits", ErrInvalid)
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, fmt.Errorf("%w: machine id: %v", ErrInvalid, err)
	}
	if id == ([16]byte{}) {
		return id, fmt.Errorf("%w: machine id is null", ErrInvalid)
	}
	return id, nil
}

// ReadMachineID reads and parses a machine-id file (MachineIDPath by default).
func ReadMachineID(path string) ([16]byte, error) {
	if path == "" {
		path = machineIDFile
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return [16]byte{}, err
	}
	return ParseMachineID(b)
}

// HostKeyFile reads the host secret from a file with the checks of
// cu.c:577-654.
type HostKeyFile struct {
	// Path of the secret; empty means $SYSTEMD_CREDENTIAL_SECRET, else DefaultHostSecretPath.
	Path string
	// MachineID is the machine id the secret must be bound to; the zero value
	// means: read MachineIDPath.
	MachineID [16]byte
}

// HostSecretPath resolves the path as cu.c:527-546 does: the environment
// override must be absolute and normalised.
func HostSecretPath() (string, error) {
	e, ok := os.LookupEnv(HostSecretEnv)
	if !ok {
		return DefaultHostSecretPath, nil
	}
	if !filepath.IsAbs(e) || filepath.Clean(e) != e || strings.HasSuffix(e, "/") {
		return "", fmt.Errorf("%w: $%s must be an absolute, normalised file path", ErrInvalid, HostSecretEnv)
	}
	return e, nil
}

func (f HostKeyFile) resolve() (string, [16]byte, error) {
	path := f.Path
	if path == "" {
		p, err := HostSecretPath()
		if err != nil {
			return "", [16]byte{}, err
		}
		path = p
	}
	mid := f.MachineID
	if mid == ([16]byte{}) {
		var err error
		if mid, err = ReadMachineID(""); err != nil {
			return "", mid, err
		}
	}
	return path, mid, nil
}

// HostKey implements HostKeySource. The file must be a regular file with one
// link and mode exactly 0400, opened without following a final symlink, from
// 17 bytes to 16 MiB; its first 16 bytes must be HostSecretMachineID.
func (f HostKeyFile) HostKey() ([]byte, error) {
	path, mid, err := f.resolve()
	if err != nil {
		return nil, err
	}
	raw, err := readHostSecret(path)
	if err != nil {
		return nil, err
	}
	return bindToMachine(raw, mid, path)
}

// bindToMachine checks the machine id prefix of a whole host secret and returns
// the key part; the secret is wiped when it belongs to another machine.
func bindToMachine(raw []byte, mid [16]byte, path string) ([]byte, error) {
	want := HostSecretMachineID(mid)
	if !hmac.Equal(raw[:16], want[:]) {
		clear(raw)
		return nil, fmt.Errorf("%w: %s", ErrHostKeyMachine, path)
	}
	return raw[16:], nil
}

// HostKeyFromFile reads the host secret from an already open file, with the
// checks of HostKey, and never opens a path: a caller that has judged the
// descriptor gets the bytes of that same file. The result is a private copy.
// machineID must not be null.
func HostKeyFromFile(f *os.File, machineID [16]byte) ([]byte, error) {
	if machineID == ([16]byte{}) {
		return nil, fmt.Errorf("%w: machine id is null", ErrInvalid)
	}
	raw, err := readHostSecretFile(f)
	if err != nil {
		return nil, err
	}
	return bindToMachine(raw, machineID, f.Name())
}

// ephemeralKey marks a HostKeySource whose HostKey result is a private copy
// that the caller may overwrite once it has used it.
type ephemeralKey interface{ ephemeralKey() }

func (HostKeyFile) ephemeralKey() {}

// CreateHostKey generates a host secret for machineID at path the way
// systemd-creds setup does (cu.c:453-514): 16 bytes of HostSecretMachineID
// then HostSecretDataSize random bytes, mode 0400, linked into place so that
// an existing file is never replaced (os.ErrExist). It returns the key part.
func CreateHostKey(path string, machineID [16]byte) ([]byte, error) {
	return createHostSecret(path, machineID)
}
