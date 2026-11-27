//go:build unix && !386 && !arm

package delivery

// wideIDRefusals are the ids no 32-bit int can hold: they exist only where int is
// 64 bits wide (on a 32-bit target the compiler refuses them before a test runs).
func wideIDRefusals() []refusalCase {
	return []refusalCase{
		{"uid that wraps to 0", 0, func(c *Config) { c.UID = 1 << 32 }, ErrBadID},
		{"gid that wraps to 0", 0, func(c *Config) { c.GID = 1 << 32 }, ErrBadID},
		{"uid -1 as the kernel reads it", 0, func(c *Config) { c.UID = 0xFFFFFFFF }, ErrBadID},
		{"gid -1 as the kernel reads it", 0, func(c *Config) { c.GID = 0xFFFFFFFF }, ErrBadID},
		{"supplementary group that wraps", 0, func(c *Config) { c.Groups = []int{1 << 32} }, ErrBadID},
	}
}
