package sdcreds

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

// Armor line widths of "systemd-creds encrypt" (creds.c:639): 79 columns, 69
// with --pretty.
const (
	ArmorWidth       = 79
	ArmorWidthPretty = 69
)

// Armor returns the Base64 text form of a credential, wrapped at width
// columns with a newline after every line, the last one included.
func Armor(blob []byte, width int) string {
	enc := base64.StdEncoding.EncodeToString(blob)
	if width <= 0 {
		return enc
	}
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/width + 1)
	for len(enc) > 0 {
		n := min(width, len(enc))
		b.WriteString(enc[:n])
		b.WriteByte('\n')
		enc = enc[n:]
	}
	return b.String()
}

// maxArmored bounds the text accepted by Unarmor: Base64 of EncryptedMax plus
// generous room for line breaks.
const maxArmored = EncryptedMax/3*4 + EncryptedMax/16 + 1024

// Unarmor decodes the Base64 text form, ignoring ASCII white space and
// accepting missing padding (the decoder of READ_FULL_FILE_UNBASE64, creds.c:690).
// Oversized input is refused before anything is allocated.
func Unarmor(text []byte) ([]byte, error) {
	if len(text) > maxArmored {
		return nil, ErrTooLarge
	}
	clean := make([]byte, 0, len(text))
	for _, c := range text {
		switch c {
		case ' ', '\t', '\n', '\r', '\v', '\f':
		default:
			clean = append(clean, c)
		}
	}
	s := strings.TrimRight(string(clean), "=")
	if len(clean)-len(s) > 2 {
		return nil, fmt.Errorf("%w: bad base64 padding", ErrFormat)
	}
	out, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if len(out) > EncryptedMax {
		return nil, ErrTooLarge
	}
	return out, nil
}

// EnvOverrides copies the two operational knobs systemd reads from the
// environment into o: SYSTEMD_CREDENTIAL_VALIDATE_NAME=0 and
// SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER=0 (cu.c:1678, 1694).
func (o *DecryptOptions) EnvOverrides() {
	o.IgnoreName = envFalse("SYSTEMD_CREDENTIAL_VALIDATE_NAME")
	o.IgnoreNotAfter = envFalse("SYSTEMD_CREDENTIAL_VALIDATE_NOT_AFTER")
}

// envFalse is true when the variable is set to a false boolean in the
// spelling of parse_boolean: 0, no, false, off, n, f.
func envFalse(name string) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "0", "no", "false", "off", "n", "f":
		return true
	}
	return false
}
