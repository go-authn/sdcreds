package sdcreds

import "encoding/binary"

// NameValid reports whether s is a valid credential name: a valid file name
// (path-util.c:1162: not empty, not "." or "..", no '/') that is also a valid
// fd name (fd-util.c:553: printable ASCII, no ':'), at most NameMax bytes
// (creds-util.c:49).
func NameValid(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > NameMax {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < ' ' || c >= 127 || c == ':' || c == '/' {
			return false
		}
	}
	return true
}

func align8(n uint64) uint64 { return (n + 7) &^ 7 }

// Header is the unencrypted, authenticated header of a credential
// (cu.c:711-747): the encrypted_credential_header and, for scoped types, the
// scoped_credential_header.
type Header struct {
	ID         KeyID
	KeySize    uint32
	BlockSize  uint32
	IVSize     uint32
	TagSize    uint32
	IV         []byte // aliases the parsed blob
	ScopeFlags uint64 // zero unless the key type is scoped

	aadLen uint64 // bytes [0, aadLen) are the GCM additional data
}

// AADLen is the length of the additional authenticated data: every header
// byte, padding included (cu.c:1204-1206).
func (h *Header) AADLen() int { return int(h.aadLen) }

// classify reads the id and refuses what phase 1 cannot handle, in systemd's
// order (cu.c:1379-1383).
func classify(blob []byte) (KeyID, error) {
	var id KeyID
	if len(blob) < len(id) {
		return id, ErrFormat
	}
	copy(id[:], blob)
	switch id {
	case IDHost, IDHostScoped, IDNull:
		return id, nil
	}
	if mode, ok := tpmIDs[id]; ok {
		return id, &UnsupportedModeError{ID: id, Known: true, Mode: mode}
	}
	return id, &UnsupportedModeError{ID: id}
}

// Parse validates the structure of blob without any key and returns its
// header. It never allocates in proportion to a size read from the input, and
// every size is bounded before it is used. blob must not exceed EncryptedMax.
// The checks follow cu.c:1412-1438 and cu.c:1550-1564 and 1591-1608.
func Parse(blob []byte) (*Header, error) {
	if uint64(len(blob)) > EncryptedMax {
		return nil, ErrTooLarge
	}
	id, err := classify(blob)
	if err != nil {
		return nil, err
	}
	n := uint64(len(blob))
	const fixed = 16 + 4*4 // id + key, block, iv, tag sizes (offsetof(iv))
	if n < fixed {
		return nil, ErrFormat
	}
	h := &Header{
		ID:        id,
		KeySize:   binary.LittleEndian.Uint32(blob[16:]),
		BlockSize: binary.LittleEndian.Uint32(blob[20:]),
		IVSize:    binary.LittleEndian.Uint32(blob[24:]),
		TagSize:   binary.LittleEndian.Uint32(blob[28:]),
	}
	if h.KeySize != keySize {
		return nil, ErrFormat
	}
	if h.BlockSize == 0 || h.BlockSize > FieldMax {
		return nil, ErrFormat
	}
	if h.IVSize > FieldMax {
		return nil, ErrFormat
	}
	if h.TagSize == 0 || h.TagSize > FieldMax {
		return nil, ErrFormat
	}
	var scoped uint64
	if id.Scoped() {
		scoped = 8
	}
	const metaMin = 8 + 8 + 4 // offsetof(metadata_credential_header, name)
	p := align8(fixed + uint64(h.IVSize))
	if n < p+scoped+align8(metaMin)+uint64(h.TagSize) {
		return nil, ErrFormat
	}
	h.IV = blob[fixed : fixed+uint64(h.IVSize)]
	if id.Scoped() {
		h.ScopeFlags = binary.LittleEndian.Uint64(blob[p:])
		if h.ScopeFlags != scopeFlags {
			return nil, &UnsupportedModeError{ID: id, Known: true, Reason: "scoped credential with unsupported flags"}
		}
		p += 8
	}
	// The cipher expectations of cu.c:1591-1608: this version speaks AES-256-GCM only.
	if h.BlockSize != blockSize || h.TagSize != tagSize || h.IVSize == 0 {
		return nil, ErrFormat
	}
	h.aadLen = p
	return h, nil
}
