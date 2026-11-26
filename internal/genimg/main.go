//go:build ignore

// Command genimg writes the empty FFS images that delivery embeds, one per size
// class, with the real newfs(8) on a vnd(4) device. It runs as root on OpenBSD:
//
//	go run internal/genimg/main.go -out delivery/images
//
// It is excluded from every build (a generator, not a shipped program).
//
// OpenBSD's newfs refuses a regular file and the kernel mounts an MFS from an
// image of the file system laid out in memory, so the image is made once here
// and committed (gzip; an empty file system is mostly zeros). The images hold no
// secret and no host-specific data other than newfs's own file-system id.
package main

import (
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// Classes are the sizes in MiB; keep in step with delivery/images_openbsd.go.
var classes = []int{1, 2, 4, 8, 16, 32, 64}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func gen(out string, mib int) (err error) {
	raw := filepath.Join(out, fmt.Sprintf("ffs-%dMiB.img", mib))
	f, err := os.OpenFile(raw, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err = f.Truncate(int64(mib) << 20); err != nil {
		f.Close()
		return err
	}
	f.Close()
	defer os.Remove(raw)
	if err = run("vnconfig", "vnd0", raw); err != nil {
		return err
	}
	defer func() {
		if uerr := run("vnconfig", "-u", "vnd0"); err == nil {
			err = uerr
		}
	}()
	// One inode per 2 KiB keeps 1024 small files inside the 1 MiB class.
	if err = run("newfs", "-q", "-O", "1", "-m", "0", "-o", "space", "-b", "4096", "-f", "512", "-i", "2048", "/dev/rvnd0c"); err != nil {
		return err
	}
	in, err := os.Open(raw)
	if err != nil {
		return err
	}
	defer in.Close()
	gz, err := os.OpenFile(filepath.Join(out, fmt.Sprintf("ffs-%dMiB.gz", mib)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	zw, _ := gzip.NewWriterLevel(gz, gzip.BestCompression)
	if _, err = io.Copy(zw, in); err != nil {
		return err
	}
	if err = zw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func main() {
	out := flag.String("out", "delivery/images", "directory of the images")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, mib := range classes {
		if err := gen(*out, mib); err != nil {
			fmt.Fprintf(os.Stderr, "genimg: %d MiB: %v\n", mib, err)
			os.Exit(1)
		}
		fmt.Printf("%d MiB done\n", mib)
	}
}
