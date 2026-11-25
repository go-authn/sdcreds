package delivery

import (
	"fmt"
	"path/filepath"
	"strconv"
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
	Owner int
	Dir   string
	MiB   int
}

func (a helperArgs) argv() []string {
	return []string{"--owner", strconv.Itoa(a.Owner), "--dir", a.Dir, "--mib", strconv.Itoa(a.MiB)}
}

// parseHelperArgs reads exactly --owner N --dir D --mib M, in that order, and
// refuses anything else: the helper runs as root and starts from a command line.
func parseHelperArgs(argv []string) (helperArgs, error) {
	var a helperArgs
	if len(argv) != 6 || argv[0] != "--owner" || argv[2] != "--dir" || argv[4] != "--mib" {
		return a, fmt.Errorf("delivery: helper arguments: want --owner N --dir D --mib M")
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
