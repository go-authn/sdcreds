//go:build !unix

package s6

// holdSignals has nothing to hold where there is no s6 to signal.
func holdSignals() (release func()) { return func() {} }
