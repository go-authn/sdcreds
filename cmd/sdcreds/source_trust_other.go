//go:build !unix

package main

import "github.com/go-authn/sdcreds/s6"

// sourceReader is nil here: s6-run is Linux only, and the package reads the
// directory itself where it is exercised.
var sourceReader func(dir string) ([]s6.Sealed, error)
