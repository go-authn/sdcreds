package sdcreds

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
	"time"
)

// Scope identifies the user a scoped credential is bound to. systemd hashes
// the uid, the raw machine id and the user name into the key
// (mangle_uid_into_key, cu.c:821-869).
type Scope struct {
	UID      uint32
	Username string
	// MachineID is the raw machine id (sd_id128_get_machine, cu.c:840; not the
	// app-specific one). The zero value means: read MachineIDPath.
	MachineID [16]byte
}

func (s *Scope) resolve() (Scope, error) {
	r := *s
	if strings.IndexByte(r.Username, 0) >= 0 {
		return r, fmt.Errorf("%w: user name contains NUL", ErrInvalid)
	}
	if r.MachineID == ([16]byte{}) {
		id, err := ReadMachineID("")
		if err != nil {
			return r, err
		}
		r.MachineID = id
	}
	return r, nil
}

// scopedHashData is the HMAC message of cu.c:758-764, packed little endian:
// flags u64, uid u32, machine id, then the user name and one NUL.
func scopedHashData(s Scope) []byte {
	b := make([]byte, 0, 8+4+16+len(s.Username)+1)
	b = binary.LittleEndian.AppendUint64(b, scopeFlags)
	b = binary.LittleEndian.AppendUint32(b, s.UID)
	b = append(b, s.MachineID[:]...)
	b = append(b, s.Username...)
	return append(b, 0)
}

// deriveKey is sha256_hash_host_and_tpm2_key then, for scoped types,
// mangle_uid_into_key (cu.c:780-869). An absent host key hashes nothing, so
// the null key is SHA256("").
func deriveKey(id KeyID, src HostKeySource, scope *Scope) ([]byte, error) {
	h := sha256.New()
	if id.UsesHostKey() {
		if src == nil {
			return nil, fmt.Errorf("%w: no host key source", ErrInvalid)
		}
		hk, err := src.HostKey()
		if err != nil {
			return nil, fmt.Errorf("sdcreds: failed to determine local credential key: %w", err)
		}
		if len(hk) == 0 {
			return nil, fmt.Errorf("%w: empty host key", ErrInvalid)
		}
		h.Write(hk)
		if _, ok := src.(ephemeralKey); ok {
			clear(hk) // the secret itself does not outlive the hash of it
		}
	}
	k := h.Sum(nil)
	if id.Scoped() {
		s, err := scope.resolve()
		if err != nil {
			return nil, err
		}
		m := hmac.New(sha256.New, k)
		m.Write(scopedHashData(s))
		k = m.Sum(nil)
	}
	return k, nil
}

// newGCM cannot fail: the key is a SHA-256 or HMAC-SHA256 output (32 bytes)
// and Parse bounds the IV to 1..FieldMax bytes, which GCM accepts.
func newGCM(key, iv []byte) cipher.AEAD {
	blk, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCMWithNonceSize(blk, len(iv))
	return g
}

func nowMicro() uint64 { return uint64(time.Now().UnixMicro()) }

// EncryptOptions configure Encrypt.
type EncryptOptions struct {
	// Key is IDNull, IDHost or IDHostScoped. TPM2 and public-key types give an
	// *UnsupportedModeError.
	Key KeyID
	// HostKey is required for IDHost and IDHostScoped.
	HostKey HostKeySource
	// Name is embedded and authenticated; empty embeds no name (as --name=).
	Name string
	// Timestamp in microseconds since the epoch; 0 means now, Infinity means none.
	Timestamp uint64
	// NotAfter in microseconds since the epoch; 0 or Infinity means never.
	NotAfter uint64
	// Scope is required for IDHostScoped and ignored otherwise.
	Scope *Scope
	// RefuseNull makes IDNull an error (CREDENTIAL_REFUSE_NULL, cu.c:1081).
	RefuseNull bool
	// Rand supplies the 12-byte IV; nil means crypto/rand, and nil is what every
	// real caller must use. A fixed or repeated IV under one key lets anyone who
	// sees two credentials recover the XOR of their plaintexts and forge
	// others: AES-GCM is catastrophically broken by a repeated nonce. The field
	// exists only so that tests and interoperability checks can inject a known
	// IV. With random 96-bit IVs a key must not seal more than 2^32 credentials
	// (NIST SP 800-38D, 8.3); a host key sealing credentials one per service is
	// far below that.
	Rand io.Reader
}

// Encrypt seals plaintext in the systemd credential binary format
// (encrypt_credential_and_warn, cu.c:871-1262). Base64 armour is up to the
// caller (see Armor).
func Encrypt(plaintext []byte, o EncryptOptions) ([]byte, error) {
	switch o.Key {
	case IDNull, IDHost, IDHostScoped:
	default:
		if mode, ok := tpmIDs[o.Key]; ok {
			return nil, &UnsupportedModeError{ID: o.Key, Known: true, Mode: mode}
		}
		return nil, fmt.Errorf("%w: invalid key type %s", ErrInvalid, o.Key)
	}
	if len(plaintext) > PlaintextMax {
		return nil, ErrTooLarge
	}
	if o.Name != "" && !NameValid(o.Name) {
		return nil, fmt.Errorf("%w: invalid credential name %q", ErrInvalid, o.Name)
	}
	ts, na := o.Timestamp, o.NotAfter
	if ts == 0 {
		ts = nowMicro()
	}
	if na == 0 {
		na = Infinity
	}
	if na != Infinity && ts != Infinity && na <= ts {
		return nil, fmt.Errorf("%w: credential is invalidated before or when it becomes valid (%d <= %d)", ErrInvalid, na, ts)
	}
	if o.Key == IDHostScoped && o.Scope == nil {
		return nil, fmt.Errorf("%w: scoped key type selected, but no user specified", ErrInvalid)
	}
	if o.Key == IDNull && o.RefuseNull {
		return nil, fmt.Errorf("%w: attempted to encrypt with null key, but this is disallowed", ErrNullRefused)
	}
	key, err := deriveKey(o.Key, o.HostKey, o.Scope)
	if err != nil {
		return nil, err
	}
	defer zero(key)

	iv := make([]byte, ivSize)
	rnd := o.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, iv); err != nil {
		return nil, fmt.Errorf("sdcreds: failed to acquire a randomized IV: %w", err)
	}
	aead := newGCM(key, iv)

	// Header: id, sizes, IV, pad to 8, then the scoped flags for scoped types.
	const fixed = 16 + 4*4
	p := align8(fixed + ivSize)
	if o.Key.Scoped() {
		p += 8
	}
	ml := align8(8 + 8 + 4 + uint64(len(o.Name)))
	total := p + ml + uint64(len(plaintext)) + tagSize
	out := make([]byte, p+ml+uint64(len(plaintext)), total)
	copy(out, o.Key[:])
	binary.LittleEndian.PutUint32(out[16:], keySize)
	binary.LittleEndian.PutUint32(out[20:], blockSize)
	binary.LittleEndian.PutUint32(out[24:], ivSize)
	binary.LittleEndian.PutUint32(out[28:], tagSize)
	copy(out[fixed:], iv)
	if o.Key.Scoped() {
		binary.LittleEndian.PutUint64(out[align8(fixed+ivSize):], scopeFlags)
	}
	// Metadata then payload, sealed in place as one GCM stream (cu.c:1208-1233).
	m := out[p:]
	binary.LittleEndian.PutUint64(m[0:], ts)
	binary.LittleEndian.PutUint64(m[8:], na)
	binary.LittleEndian.PutUint32(m[16:], uint32(len(o.Name)))
	copy(m[20:], o.Name)
	copy(m[ml:], plaintext)
	// The AAD is every header byte, padding included (cu.c:1204-1206).
	aead.Seal(out[p:p], iv, out[p:], out[:p])
	return out[:total], nil
}

// Metadata is the authenticated metadata of a decrypted credential
// (metadata_credential_header, cu.c:749-756). Timestamps are microseconds
// since the epoch, Infinity when absent.
type Metadata struct {
	Timestamp uint64
	NotAfter  uint64
	Name      string
}

// DecryptOptions configure Decrypt.
type DecryptOptions struct {
	// HostKey is required for IDHost and IDHostScoped credentials.
	HostKey HostKeySource
	// Name is the expected credential name; nil validates nothing, as
	// systemd-creds --name= does. A non-empty embedded name must equal it.
	Name *string
	// Timestamp is the time not-after is compared with, in microseconds; 0
	// means now and Infinity skips the check (cu.c:1688).
	Timestamp uint64
	// Scope selects user scope. A scoped credential needs it; an unscoped one
	// refuses it unless AnyScope is set (cu.c:1401-1410).
	Scope    *Scope
	AnyScope bool
	// AllowNull accepts a null-key credential outright; RefuseNull refuses it;
	// otherwise NullPolicy decides (see SystemNullPolicy). With none of the
	// three set the null key is refused: anyone can seal with it.
	AllowNull  bool
	RefuseNull bool
	NullPolicy func() error
	// RequireName makes the embedded name mandatory: a credential without one
	// is refused instead of passing any name check. It needs Name, and it
	// overrides IgnoreName.
	RequireName bool
	// IgnoreName and IgnoreNotAfter are the effect of
	// SYSTEMD_CREDENTIAL_VALIDATE_NAME=0 and _NOT_AFTER=0 (cu.c:1678, 1694);
	// see EnvOverrides.
	IgnoreName     bool
	IgnoreNotAfter bool
}

// Decrypt opens a credential written by systemd-creds or by Encrypt, running
// the checks of decrypt_credential_and_warn (cu.c:1334-1716) in the same
// order. blob is the binary form (see Unarmor); it is not modified.
func Decrypt(blob []byte, o DecryptOptions) ([]byte, Metadata, error) {
	var md Metadata
	if uint64(len(blob)) > EncryptedMax {
		return nil, md, ErrTooLarge
	}
	if o.RequireName && o.Name == nil {
		return nil, md, fmt.Errorf("%w: RequireName needs the expected Name", ErrInvalid)
	}
	id, err := classify(blob)
	if err != nil {
		return nil, md, err
	}
	if id == IDNull {
		switch {
		case o.RefuseNull:
			return nil, md, fmt.Errorf("%w: credential uses null key, but that's not allowed", ErrNullRefused)
		case o.AllowNull:
		case o.NullPolicy != nil:
			if err := o.NullPolicy(); err != nil {
				return nil, md, err
			}
		default:
			// The null key is a public constant: a credential sealed with it
			// proves nothing, so it is accepted only when the caller says so.
			return nil, md, fmt.Errorf("%w: credential uses the null key, which needs AllowNull or a NullPolicy", ErrNullRefused)
		}
	}
	if id.Scoped() {
		if o.Scope == nil {
			return nil, md, fmt.Errorf("%w: encrypted file is scoped to a user, but no user selected", ErrScope)
		}
	} else if o.Scope != nil && !o.AnyScope {
		return nil, md, fmt.Errorf("%w: encrypted file is scoped to the system, but user scope selected", ErrScope)
	}
	h, err := Parse(blob)
	if err != nil {
		return nil, md, err
	}
	var scope *Scope
	if id.Scoped() {
		scope = o.Scope
	}
	key, err := deriveKey(id, o.HostKey, scope)
	if err != nil {
		return nil, md, err
	}
	defer zero(key)
	aead := newGCM(key, h.IV)
	p := h.aadLen
	pt, err := aead.Open(nil, h.IV, blob[p:], blob[:p])
	if err != nil {
		return nil, md, ErrAuth
	}

	// Parse guarantees len(pt) >= align8(metaMin): the fixed fields are there.
	const metaMin = 8 + 8 + 4
	md.Timestamp = binary.LittleEndian.Uint64(pt[0:])
	md.NotAfter = binary.LittleEndian.Uint64(pt[8:])
	nameSize := binary.LittleEndian.Uint32(pt[16:])
	fail := func(err error) ([]byte, Metadata, error) {
		zero(pt)
		return nil, Metadata{}, err
	}
	if md.Timestamp != Infinity && md.NotAfter != Infinity && md.Timestamp >= md.NotAfter {
		return fail(fmt.Errorf("%w: timestamps of credential are not in order", ErrFormat))
	}
	// A name longer than NameMax is refused below by NameValid.
	hs := align8(metaMin + uint64(nameSize))
	if uint64(len(pt)) < hs {
		return fail(fmt.Errorf("%w: metadata header incomplete", ErrFormat))
	}
	if nameSize == 0 && o.RequireName {
		return fail(fmt.Errorf("%w: credential carries no name, expected %q", ErrNameMismatch, *o.Name))
	}
	if nameSize > 0 {
		name := string(pt[20 : 20+nameSize])
		if strings.IndexByte(name, 0) >= 0 || !NameValid(name) {
			return fail(fmt.Errorf("%w: embedded credential name is not valid", ErrFormat))
		}
		md.Name = name
		if o.Name != nil && name != *o.Name && (!o.IgnoreName || o.RequireName) {
			return fail(fmt.Errorf("%w: embedded name %q, expected %q", ErrNameMismatch, name, *o.Name))
		}
	}
	now := o.Timestamp
	if now == 0 {
		now = nowMicro()
	}
	if now != Infinity && md.NotAfter != Infinity && md.NotAfter < now && !o.IgnoreNotAfter {
		return fail(ErrExpired)
	}
	out := make([]byte, uint64(len(pt))-hs)
	copy(out, pt[hs:])
	zero(pt)
	return out, md, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
