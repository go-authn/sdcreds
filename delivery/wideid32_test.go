//go:build unix && (386 || arm)

package delivery

// wideIDRefusals: a 32-bit int cannot hold an id past 32 bits, so there is no case.
func wideIDRefusals() []refusalCase { return nil }
