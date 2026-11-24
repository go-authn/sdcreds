package sdcreds_test

import (
	"errors"
	"testing"

	"github.com/go-authn/sdcreds"
)

// A flipped bit anywhere in the sealed part is an authentication failure,
// reported as such and never as a panic on the empty plaintext.
func TestTamperIsAuthFailure(t *testing.T) {
	ok := nullBlob(t)
	for i := 48; i < len(ok); i += 7 {
		b := append([]byte(nil), ok...)
		b[i] ^= 1
		safely(t, "flip", func() {
			if _, _, err := sdcreds.Decrypt(b, sdcreds.DecryptOptions{AllowNull: true}); err == nil {
				t.Errorf("byte %d: accepted", i)
			}
		})
	}
	b := append([]byte(nil), ok...)
	b[len(b)-1] ^= 1
	safely(t, "tag", func() {
		if _, _, err := sdcreds.Decrypt(b, sdcreds.DecryptOptions{AllowNull: true}); !errors.Is(err, sdcreds.ErrAuth) {
			t.Errorf("tag: %v", err)
		}
	})
}
