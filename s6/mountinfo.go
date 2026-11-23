package s6

import (
	"slices"
	"strconv"
	"strings"
)

// mountSourceIn reads the mount table in the format of proc_pid_mountinfo(5)
// and returns the source of the topmost mount whose mount point is dir (the
// last line that names it), and whether there is one.
func mountSourceIn(table, dir string) (src string, mounted bool) {
	for line := range strings.SplitSeq(table, "\n") {
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		// mount point is field 5; after the separator: fs type, source, options
		if sep < 6 || len(f) < sep+3 {
			continue
		}
		if unescapeMountinfo(f[4]) == dir {
			src, mounted = unescapeMountinfo(f[sep+2]), true
		}
	}
	return src, mounted
}

// unescapeMountinfo undoes the octal escapes (\040 for a space) of the kernel.
func unescapeMountinfo(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
