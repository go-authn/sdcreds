package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

// safely makes a panic an ordinary failure of the assertion that follows.
func safely[T any](f func() T) (v T, perr any) {
	defer func() { perr = recover() }()
	return f(), nil
}

func TestMedian(t *testing.T) {
	ms := time.Millisecond
	if _, p := safely(func() time.Duration { return median(nil) }); p != nil {
		t.Errorf("median of nothing panicked: %v", p)
	}
	if got, p := safely(func() time.Duration { return median([]time.Duration{7 * ms}) }); p != nil || got != 7*ms {
		t.Errorf("median of one: %v %v", got, p)
	}
	for _, c := range []struct {
		in   []time.Duration
		want time.Duration
	}{
		{nil, 0}, {[]time.Duration{5 * ms}, 5 * ms}, {[]time.Duration{9 * ms, 1 * ms, 5 * ms}, 5 * ms},
		{[]time.Duration{4 * ms, 1 * ms, 2 * ms, 9 * ms}, 3 * ms},
	} {
		if got, p := safely(func() time.Duration { return median(slices.Clone(c.in)) }); got != c.want || p != nil {
			t.Errorf("%v: %v (panic %v), want %v", c.in, got, p, c.want)
		}
	}
}

func TestParseSizes(t *testing.T) {
	if got, err := parseSizes("1, 4096,65536"); err != nil || len(got) != 3 || got[0] != 1 || got[1] != 4096 || got[2] != 65536 {
		t.Errorf("%v %v", got, err)
	}
	for _, bad := range []string{"", "0", "-1", "x", "1,,2", "1,0"} {
		if _, err := parseSizes(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLabel(t *testing.T) {
	for n, want := range map[int]string{1: "1 B", 1023: "1023 B", 1024: "1 KiB", 4096: "4 KiB", 1025: "1025 B", 1 << 20: "1 MiB", 3 << 20: "3 MiB", 1<<20 + 1024: "1025 KiB"} {
		if got := label(n); got != want {
			t.Errorf("%d: %q, want %q", n, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	defer func(o string) { loadFile = o }(loadFile)
	dir := t.TempDir()
	loadFile = filepath.Join(dir, "none")
	if _, err := load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	for content, ok := range map[string]bool{"": false, "  \n": false, "x 1 2": false, "7.50 6 5 1/2 3": true} {
		loadFile = filepath.Join(dir, "l")
		os.WriteFile(loadFile, []byte(content), 0o644)
		type res struct {
			l   float64
			err error
		}
		r, p := safely(func() res { l, err := load(); return res{l, err} })
		if p != nil || (r.err == nil) != ok || ok && r.l != 7.5 {
			t.Errorf("%q: %v %v %v", content, r.l, r.err, p)
		}
		if content == "" && (r.err == nil || !strings.Contains(r.err.Error(), "empty")) {
			t.Errorf("empty file: %v", r.err)
		}
	}
}

// A stand-in tool: a shell script that copies its input, so the harness can be
// run end to end without systemd-creds.
func fakeTool(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in tool is a shell script")
	}
	p := filepath.Join(t.TempDir(), "tool")
	script := "#!/bin/sh\n" + body
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	copyTool := fakeTool(t, `eval "in=\${$(($#-1))}"; eval "out=\${$#}"; cp "$in" "$out"`+"\n")
	var out, errb bytes.Buffer
	if rc := run([]string{"-ours", copyTool, "-theirs", copyTool, "-rounds", "3", "-sizes", "1,2048", "-max-load", "-1"}, &out, &errb); rc != 0 {
		t.Fatalf("rc %d: %s", rc, errb.String())
	}
	s := out.String()
	for _, want := range []string{"| 1 B | encrypt |", "| 1 B | decrypt |", "| 2 KiB | encrypt |", "| 2 KiB | decrypt |", "| ratio |", "median of 3 interleaved rounds"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q missing from:\n%s", want, s)
		}
	}
}

func TestRunNamesTheFailingOperation(t *testing.T) {
	copyBody := `eval "in=\${$(($#-1))}"; eval "out=\${$#}"; cp "$in" "$out"` + "\n"
	good := fakeTool(t, copyBody)
	for _, op := range []string{"encrypt", "decrypt"} {
		bad := fakeTool(t, `[ "$1" = `+op+` ] && exit 3`+"\n"+copyBody)
		var out, errb bytes.Buffer
		rc := run([]string{"-ours", bad, "-theirs", good, "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, &out, &errb)
		if rc != 1 || !strings.Contains(errb.String(), "["+op+" ") {
			t.Errorf("%s: rc %d: %s", op, rc, errb.String())
		}
	}
	var out, errb bytes.Buffer
	if rc := run([]string{"-nope"}, &out, &errb); rc != 2 {
		t.Errorf("unknown flag: rc %d", rc)
	}
	t.Setenv("TMPDIR", filepath.Join(t.TempDir(), "none"))
	errb.Reset()
	if rc := run([]string{"-ours", good, "-theirs", good, "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "perf") {
		t.Errorf("no temporary directory: rc %d: %s", rc, errb.String())
	}
}

func TestRunReportsAPayloadThatCannotBeWritten(t *testing.T) {
	good := fakeTool(t, `eval "in=\${$(($#-1))}"; eval "out=\${$#}"; cp "$in" "$out"`+"\n")
	defer func(o func(string, []byte, os.FileMode) error) { writeFile = o }(writeFile)
	writeFile = func(string, []byte, os.FileMode) error { return errors.New("no space left") }
	var out, errb bytes.Buffer
	if rc := run([]string{"-ours", good, "-theirs", good, "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, &out, &errb); rc != 1 || !strings.Contains(errb.String(), "no space left") {
		t.Errorf("rc %d: %s", rc, errb.String())
	}
}

func TestRunRefusals(t *testing.T) {
	good := fakeTool(t, `eval "in=\${$(($#-1))}"; eval "out=\${$#}"; cp "$in" "$out"`+"\n")
	bad := fakeTool(t, "exit 3\n")
	corrupt := fakeTool(t, `eval "out=\${$#}"; echo wrong > "$out"`+"\n")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"no tool":        {[]string{"-max-load", "-1"}, "-ours is required"},
		"no rounds":      {[]string{"-ours", good, "-rounds", "0", "-max-load", "-1"}, "at least 1"},
		"bad sizes":      {[]string{"-ours", good, "-sizes", "x", "-max-load", "-1"}, "bad size"},
		"failing tool":   {[]string{"-ours", bad, "-theirs", good, "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, "exit status 3"},
		"wrong payload":  {[]string{"-ours", corrupt, "-theirs", good, "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, "different payload"},
		"unknown flag":   {[]string{"-nope"}, ""},
		"missing binary": {[]string{"-ours", "/no/such/tool", "-rounds", "1", "-sizes", "1", "-max-load", "-1"}, "no such file"},
	} {
		var out, errb bytes.Buffer
		rc := run(c.args, &out, &errb)
		if rc == 0 || !strings.Contains(errb.String(), c.want) {
			t.Errorf("%s: rc %d: %s", name, rc, errb.String())
		}
	}
	// The load gate: unknown load and a load above the limit both refuse.
	defer func(o string) { loadFile = o }(loadFile)
	loadFile = filepath.Join(t.TempDir(), "none")
	var out, errb bytes.Buffer
	if rc := run([]string{"-ours", good, "-rounds", "1", "-sizes", "1"}, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "load is unknown") {
		t.Errorf("unknown load: rc %d: %s", rc, errb.String())
	}
	loadFile = filepath.Join(t.TempDir(), "l")
	os.WriteFile(loadFile, []byte("9.00 1 1 1/1 1\n"), 0o644)
	errb.Reset()
	if rc := run([]string{"-ours", good, "-rounds", "1", "-sizes", "1"}, &out, &errb); rc == 0 || !strings.Contains(errb.String(), "above 8.0") {
		t.Errorf("high load: rc %d: %s", rc, errb.String())
	}
	os.WriteFile(loadFile, []byte("8.00 1 1 1/1 1\n"), 0o644)
	errb.Reset()
	if rc := run([]string{"-ours", good, "-theirs", good, "-rounds", "1", "-sizes", "1"}, &out, &errb); rc != 0 {
		t.Errorf("load at the limit refused: %s", errb.String())
	}
}
