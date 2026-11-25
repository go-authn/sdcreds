//go:build unix

package main

import (
	"os"
	"testing"
)

// trustSource makes the test the owner the s6-run source is judged against.
func trustSource(t *testing.T) { asOwner(t, uint32(os.Getuid())) }
