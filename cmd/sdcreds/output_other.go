//go:build !unix

package main

import "os"

// openExclusive creates name, which must not exist.
func openExclusive(name string) (*os.File, error) {
	return os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
}
