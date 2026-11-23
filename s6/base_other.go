//go:build !unix

package s6

// checkBase has no owner or mode to check off unix.
func checkBase(string) error { return nil }
