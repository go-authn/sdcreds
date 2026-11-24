package sdcreds

import (
	"errors"
	"fmt"
)

// Sentinel errors, one per errno systemd uses for the same refusal
// (creds-util.c:1363-1374). Compare with errors.Is.
var (
	// ErrFormat is a corrupted or truncated credential (EBADMSG).
	ErrFormat = errors.New("sdcreds: corrupted credential")
	// ErrAuth is a failed GCM tag check: wrong key or tampered data (EBADMSG,
	// cu.c:1644). It also matches ErrFormat, as in systemd.
	ErrAuth = fmt.Errorf("%w: authentication failed", ErrFormat)
	// ErrNameMismatch is a name binding failure (EDESTADDRREQ, cu.c:1682).
	ErrNameMismatch = errors.New("sdcreds: embedded credential name does not match the expected name")
	// ErrExpired is a credential past its not-after time (ESTALE, cu.c:1698).
	ErrExpired = errors.New("sdcreds: credential's time passed")
	// ErrScope is a user-scoped credential opened in system scope, or the
	// reverse (EMEDIUMTYPE, cu.c:1403-1407).
	ErrScope = errors.New("sdcreds: credential scope does not match the requested scope")
	// ErrNullRefused is a null-key credential refused by policy (EHWPOISON, cu.c:1291-1320).
	ErrNullRefused = errors.New("sdcreds: null-key credential refused")
	// ErrTooLarge is an input over a documented limit, refused before allocation (E2BIG).
	ErrTooLarge = errors.New("sdcreds: input too large")
	// ErrInvalid is an invalid argument (EINVAL): bad name, timestamps out of order, no key.
	ErrInvalid = errors.New("sdcreds: invalid argument")
)

// UnsupportedModeError reports a key type this version cannot handle. Known is
// true for the TPM2 and public-key types systemd defines (phases 2 and 3) and
// false for an unrecognised id (EOPNOTSUPP, cu.c:1382).
type UnsupportedModeError struct {
	ID     KeyID
	Known  bool
	Mode   string // short description when Known
	Reason string // extra detail, e.g. for unsupported scope flags
}

func (e *UnsupportedModeError) Error() string {
	switch {
	case e.Reason != "":
		return "sdcreds: unsupported credential: " + e.Reason
	case e.Known:
		return fmt.Sprintf("sdcreds: credential mode %q (id %s) needs a TPM2 and is not supported yet", e.Mode, e.ID)
	default:
		return fmt.Sprintf("sdcreds: unknown encryption format, or corrupted data (id %s)", e.ID)
	}
}
