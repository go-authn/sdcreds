//go:build !unix

package delivery

import "errors"

// ReadSource reports ErrUnsupported off unix.
func ReadSource(dir string) ([]Credential, error) { return nil, ErrUnsupported }

// ReadSourceTrusted reports ErrUnsupported off unix.
func ReadSourceTrusted(dir string, owner uint32, from string) ([]Credential, error) {
	return nil, ErrUnsupported
}

// ErrUntrustedSource is a source that someone else could have changed.
var ErrUntrustedSource = errors.New("delivery: untrusted credential source")
