//go:build !unix

package delivery

// ReadSource reports ErrUnsupported off unix.
func ReadSource(dir string) ([]Credential, error) { return nil, ErrUnsupported }
