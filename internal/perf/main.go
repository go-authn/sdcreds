// Command perf measures two credential command lines against each other,
// encrypt and decrypt of the same payload, interleaved round by round, and
// prints a Markdown table of medians. Both tools are driven with the same
// arguments, so it compares sdcreds with systemd-creds as a user runs them:
//
//	perf -ours ./sdcreds -theirs systemd-creds -rounds 21
//
// It refuses to measure when the machine's 1-minute load is above -max-load
// (default 8): a time taken under load measures the load.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

// loadFile is where the 1-minute load average is read from.
var loadFile = "/proc/loadavg"

// load returns the 1-minute load average.
func load() (float64, error) {
	b, err := os.ReadFile(loadFile)
	if err != nil {
		return 0, err
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0, errors.New("empty " + loadFile)
	}
	return strconv.ParseFloat(f[0], 64)
}

// median of d, which it sorts; zero for no samples.
func median(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	slices.Sort(d)
	if len(d)%2 == 1 {
		return d[len(d)/2]
	}
	return (d[len(d)/2-1] + d[len(d)/2]) / 2
}

// parseSizes reads "1,4096,65536" into positive sizes.
func parseSizes(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("bad size %q", f)
		}
		out = append(out, n)
	}
	return out, nil
}

func label(n int) string {
	switch {
	case n >= 1<<20 && n%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", n>>20)
	case n >= 1<<10 && n%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", n>>10)
	}
	return fmt.Sprintf("%d B", n)
}

type sample struct {
	size int
	op   string
	tool int
}

func timed(bin string, args ...string) (time.Duration, error) {
	cmd := exec.Command(bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	err := cmd.Run()
	d := time.Since(start)
	if err != nil {
		return 0, fmt.Errorf("%s %v: %v: %s", bin, args, err, stderr.String())
	}
	return d, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("perf", flag.ContinueOnError)
	fs.SetOutput(stderr)
	ours := fs.String("ours", "", "path of the sdcreds binary")
	theirs := fs.String("theirs", "systemd-creds", "the reference tool")
	rounds := fs.Int("rounds", 21, "interleaved rounds")
	sizes := fs.String("sizes", "1,4096,65536,1048576", "payload sizes in bytes")
	maxLoad := fs.Float64("max-load", 8, "refuse above this 1-minute load; negative skips the check")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "perf:", err)
		return 1
	}
	if *ours == "" || *rounds < 1 {
		return fail(errors.New("-ours is required and -rounds must be at least 1"))
	}
	sz, err := parseSizes(*sizes)
	if err != nil {
		return fail(err)
	}
	if *maxLoad >= 0 {
		l, err := load()
		if err != nil {
			return fail(fmt.Errorf("the load is unknown (%v): not measuring", err))
		}
		if l > *maxLoad {
			return fail(fmt.Errorf("1-minute load %.1f is above %.1f: not measuring", l, *maxLoad))
		}
	}
	dir, err := os.MkdirTemp("", "perf")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)
	tools := []string{*ours, *theirs}
	got := map[sample][]time.Duration{}
	for r := 0; r < *rounds; r++ {
		for _, n := range sz {
			plain := filepath.Join(dir, "plain")
			if err := os.WriteFile(plain, bytes.Repeat([]byte{byte(n)}, n), 0o600); err != nil {
				return fail(err)
			}
			// The order alternates, so neither tool always runs second.
			order := []int{0, 1}
			if r%2 == 1 {
				order = []int{1, 0}
			}
			for _, ti := range order {
				enc, dec := filepath.Join(dir, fmt.Sprintf("enc%d", ti)), filepath.Join(dir, fmt.Sprintf("dec%d", ti))
				os.Remove(enc)
				d, err := timed(tools[ti], "encrypt", "--with-key=host", "--name=", plain, enc)
				if err != nil {
					return fail(err)
				}
				got[sample{n, "encrypt", ti}] = append(got[sample{n, "encrypt", ti}], d)
				os.Remove(dec)
				d, err = timed(tools[ti], "decrypt", "--name=", enc, dec)
				if err != nil {
					return fail(err)
				}
				got[sample{n, "decrypt", ti}] = append(got[sample{n, "decrypt", ti}], d)
				if b, err := os.ReadFile(dec); err != nil || !bytes.Equal(b, bytes.Repeat([]byte{byte(n)}, n)) {
					return fail(fmt.Errorf("%s decrypted a different payload (%v)", tools[ti], err))
				}
			}
		}
	}
	fmt.Fprintf(stdout, "| payload | operation | sdcreds | %s | ratio |\n|---|---|---|---|---|\n", filepath.Base(*theirs))
	for _, n := range sz {
		for _, op := range []string{"encrypt", "decrypt"} {
			a, b := median(got[sample{n, op, 0}]), median(got[sample{n, op, 1}])
			fmt.Fprintf(stdout, "| %s | %s | %.2f ms | %.2f ms | %.2f |\n", label(n), op,
				float64(a.Microseconds())/1000, float64(b.Microseconds())/1000, float64(a)/float64(b))
		}
	}
	fmt.Fprintf(stdout, "\nmedian of %d interleaved rounds, wall time of the whole process, host key mode.\n", *rounds)
	return 0
}
