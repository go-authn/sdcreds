//go:build !unix

package main

import "testing"

// trustSource: there is no trust walk here, and s6-run is unsupported.
func trustSource(*testing.T) {}
