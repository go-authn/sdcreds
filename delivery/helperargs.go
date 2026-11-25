package delivery

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// Image classes, in MiB: the memory file system is one of these sizes (the
// embedded images, see images_openbsd.go). Capacity is what a mounted class
// offers, measured with statfs on OpenBSD 8.0 and rounded down; inodes likewise.
type class struct {
	MiB    int
	DataKB int // usable kilobytes
	Inodes int // free inodes besides the root
}

var classes = []class{
	{1, 880, 500},
	{2, 1800, 1000},
	{4, 3700, 2000},
	{8, 7500, 4000},
	{16, 15000, 8000},
	{32, 30000, 16000},
	{64, 60000, 32000},
}

// fsBlock is the block size of the images.
const fsBlock = 4096

// need is the space a set of files asks of a file system of the images' make,
// counted pessimistically: every file in whole blocks, a block of indirection
// per 1024 beyond the 12 direct ones, and a root directory with one entry per
// file in 512-byte chunks.
func need(names []string, sizes []int) (kb, inodes int) {
	bytes := 0
	dir := 0
	for i, s := range sizes {
		blocks := (s + fsBlock - 1) / fsBlock
		bytes += blocks * fsBlock
		if blocks > 12 {
			bytes += ((blocks-12)/1024 + 1) * fsBlock
		}
		dir += (8 + len(names[i]) + 1 + 3) &^ 3
	}
	bytes += (dir/512 + 2) * 512
	return (bytes + 1023) / 1024, len(sizes)
}

// pickClass returns the smallest class that holds the files, with a margin of
// one block per file and 10 % of the data kept free.
func pickClass(names []string, sizes []int) (class, error) {
	kb, inodes := need(names, sizes)
	for _, c := range classes {
		if kb*11/10 <= c.DataKB && inodes+2 <= c.Inodes {
			return c, nil
		}
	}
	return class{}, fmt.Errorf("delivery: %d files of %d KiB do not fit the largest image: %w", len(sizes), kb, ErrTooManyEntry)
}

func classByMiB(mib int) (class, bool) {
	for _, c := range classes {
		if c.MiB == mib {
			return c, true
		}
	}
	return class{}, false
}

// helperArgs are the arguments of the helper process (after HelperCommand).
type helperArgs struct {
	Owner  int
	Dir    string
	MiB    int
	UID    int
	GID    int
	Groups []int
	Exe    string
}

func (a helperArgs) argv() []string {
	gs := ""
	for i, g := range a.Groups {
		if i > 0 {
			gs += ","
		}
		gs += strconv.Itoa(g)
	}
	return []string{"--owner", strconv.Itoa(a.Owner), "--dir", a.Dir, "--mib", strconv.Itoa(a.MiB),
		"--uid", strconv.Itoa(a.UID), "--gid", strconv.Itoa(a.GID), "--groups", gs, "--exe", a.Exe}
}

// parseID reads a decimal id of 32 bits and judges it as ValidID does.
func parseID(s, what string) (int, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || (len(s) > 1 && s[0] == '0') {
		return 0, fmt.Errorf("delivery: helper arguments: bad %s %q", what, s)
	}
	if n > 0xFFFFFFFF {
		n = 0xFFFFFFFF
	}
	if err := ValidID(int64(n), what); err != nil {
		return 0, fmt.Errorf("delivery: helper arguments: %w", err)
	}
	return int(n), nil
}

// parseHelperArgs reads exactly --owner N --dir D --mib M --uid U --gid G
// --groups G1,G2 --exe E, in that order, and refuses anything else: the helper
// runs as root and starts from a command line.
func parseHelperArgs(argv []string) (helperArgs, error) {
	var a helperArgs
	if len(argv) != 14 || argv[0] != "--owner" || argv[2] != "--dir" || argv[4] != "--mib" ||
		argv[6] != "--uid" || argv[8] != "--gid" || argv[10] != "--groups" || argv[12] != "--exe" {
		return a, fmt.Errorf("delivery: helper arguments: want --owner N --dir D --mib M --uid U --gid G --groups G1,G2 --exe E")
	}
	var err error
	if a.UID, err = parseID(argv[7], "uid"); err != nil {
		return a, err
	}
	if a.GID, err = parseID(argv[9], "gid"); err != nil {
		return a, err
	}
	if argv[11] != "" {
		parts := strings.Split(argv[11], ",")
		if len(parts) > maxGroups {
			return a, fmt.Errorf("delivery: helper arguments: more than %d groups", maxGroups)
		}
		for _, s := range parts {
			g, err := parseID(s, "group")
			if err != nil {
				return a, err
			}
			a.Groups = append(a.Groups, g)
		}
	}
	if e := argv[13]; !filepath.IsAbs(e) || filepath.Clean(e) != e || len(e) > maxExeLen {
		return a, fmt.Errorf("delivery: helper arguments: bad executable %q", e)
	} else {
		a.Exe = e
	}
	n, err := strconv.ParseUint(argv[1], 10, 31)
	if err != nil || n < 2 {
		return a, fmt.Errorf("delivery: helper arguments: bad owner %q", argv[1])
	}
	a.Owner = int(n)
	d := argv[3]
	if !filepath.IsAbs(d) || filepath.Clean(d) != d || d == "/" || len(d) > maxDirLen {
		return a, fmt.Errorf("delivery: helper arguments: bad directory %q", d)
	}
	a.Dir = d
	m, err := strconv.Atoi(argv[5])
	if err != nil {
		return a, fmt.Errorf("delivery: helper arguments: bad size %q", argv[5])
	}
	if _, ok := classByMiB(m); !ok {
		return a, fmt.Errorf("delivery: helper arguments: no image of %d MiB", m)
	}
	a.MiB = m
	return a, nil
}
