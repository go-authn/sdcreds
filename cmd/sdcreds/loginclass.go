package main

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// The resource limits of a login class, read from login.conf(5) and applied to
// the program (--class). Only the nine limits below are interpreted; every
// other capability of the class (paths, priority, umask, authentication...) is
// ignored, and `run` says so in its help. A value that is present but that
// this file cannot read refuses the run: a limit that fails to apply must not
// become no limit.

// maxTCDepth bounds the tc= chain of a class.
const maxTCDepth = 8

// limitNames maps a login.conf capability to the resource it limits.
var limitNames = map[string]string{
	"cputime":      "cpu",
	"filesize":     "fsize",
	"datasize":     "data",
	"stacksize":    "stack",
	"coredumpsize": "core",
	"memoryuse":    "rss",
	"memorylocked": "memlock",
	"maxproc":      "nproc",
	"openfiles":    "nofile",
}

// limitOrder fixes the order of the resources in an encoding.
var limitOrder = []string{"cpu", "fsize", "data", "stack", "core", "rss", "memlock", "nproc", "nofile"}

// limitValue is one side of a limit: unset, infinity, or a number.
type limitValue struct {
	Set, Inf bool
	N        uint64
}

// classRlimit is the limit of one resource: the soft (Cur) and the hard (Max)
// value, either of which may be unset.
type classRlimit struct {
	Resource string
	Cur, Max limitValue
}

var errClassLimit = errors.New("login class limit")

// loginEntries returns the capability fields of every entry of a login.conf(5)
// text, by name and alias. A record is its first line and every line after a
// line that ends in a backslash; a record starts on a line that does not begin
// with white space or '#'. The fields are separated by ':'.
func loginEntries(data string) map[string][]string {
	entries := map[string][]string{}
	var rec strings.Builder
	flush := func() {
		text := rec.String()
		rec.Reset()
		fields := strings.Split(text, ":")
		var caps []string
		for _, f := range fields[1:] {
			if f = strings.TrimSpace(f); f != "" {
				caps = append(caps, f)
			}
		}
		for _, n := range strings.Split(fields[0], "|") {
			if n = strings.TrimSpace(n); n != "" {
				if _, dup := entries[n]; !dup { // the first definition wins, as cgetent
					entries[n] = caps
				}
			}
		}
	}
	cont := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if cont {
			line = strings.TrimLeft(line, " \t")
		} else if line == "" || line[0] == '#' || line[0] == ' ' || line[0] == '\t' {
			continue
		}
		cont = strings.HasSuffix(line, "\\")
		rec.WriteString(strings.TrimSuffix(line, "\\"))
		if !cont {
			flush()
		}
	}
	flush()
	return entries
}

// parseLimitValue reads "infinity", "unlimited", or a number with an optional
// size suffix b, k, m, g, t (cputime: s, m, h, d, w), as login.conf writes
// them. Anything else, an overflow included, is an error.
func parseLimitValue(resource, v string) (limitValue, error) {
	switch strings.ToLower(v) {
	case "infinity", "unlimited":
		return limitValue{Set: true, Inf: true}, nil
	}
	i := 0
	for i < len(v) && v[i] >= '0' && v[i] <= '9' {
		i++
	}
	// an empty digit run is ParseUint's error: "" and "k" are refused there
	n, err := strconv.ParseUint(v[:i], 10, 63)
	if err != nil {
		return limitValue{}, fmt.Errorf("%w: %s=%q", errClassLimit, resource, v)
	}
	mult := uint64(1)
	if suf := strings.ToLower(v[i:]); suf != "" {
		var table map[string]uint64
		if resource == "cpu" {
			table = map[string]uint64{"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
		} else {
			table = map[string]uint64{"b": 512, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}
		}
		m, ok := table[suf]
		if !ok {
			return limitValue{}, fmt.Errorf("%w: %s=%q", errClassLimit, resource, v)
		}
		mult = m
	}
	if n > math.MaxInt64/mult {
		return limitValue{}, fmt.Errorf("%w: %s=%q overflows", errClassLimit, resource, v)
	}
	return limitValue{Set: true, N: n * mult}, nil
}

// ClassLimits resolves the limits of class. lookup returns the capability
// fields of a class by name (false: not defined); the fields of the class
// itself win over those of the classes its tc= names, which are followed to
// maxTCDepth. A tc= loop or a missing class is an error.
func ClassLimits(class string, lookup func(string) ([]string, bool)) ([]classRlimit, error) {
	got := map[string]*classRlimit{}
	seen := map[string]bool{} // "resource-cur" etc. already decided
	visited := map[string]bool{}
	var walk func(name string, depth int) error
	walk = func(name string, depth int) error {
		if depth > maxTCDepth {
			return fmt.Errorf("%w: tc= chain longer than %d", errClassLimit, maxTCDepth)
		}
		if visited[name] {
			return fmt.Errorf("%w: tc= loop at %q", errClassLimit, name)
		}
		visited[name] = true
		caps, ok := lookup(name)
		if !ok {
			return fmt.Errorf("%w: class %q is not defined", errClassLimit, name)
		}
		var tcs []string
		for _, c := range caps {
			if rest, ok := strings.CutPrefix(c, "tc="); ok {
				tcs = append(tcs, rest)
				continue
			}
			key, val, hasVal := strings.Cut(c, "=")
			if !hasVal {
				key, val, hasVal = strings.Cut(c, "#")
			}
			negated := !hasVal && strings.HasSuffix(key, "@")
			key = strings.TrimSuffix(key, "@")
			base, side := key, ""
			for _, s := range []string{"-cur", "-max"} {
				if b, ok := strings.CutSuffix(key, s); ok {
					base, side = b, s
				}
			}
			res, isLimit := limitNames[base]
			if !isLimit {
				continue
			}
			if !hasVal {
				// "openfiles@" removes the capability from here on; a bare name is
				// not a value.
				if negated {
					for _, s := range []string{"-cur", "-max"} {
						if side == "" || side == s {
							seen[res+s] = true
						}
					}
					continue
				}
				return fmt.Errorf("%w: %q has no value", errClassLimit, c)
			}
			v, err := parseLimitValue(res, val)
			if err != nil {
				return err
			}
			r := got[res]
			if r == nil {
				r = &classRlimit{Resource: res}
				got[res] = r
			}
			if (side == "" || side == "-cur") && !seen[res+"-cur"] {
				r.Cur, seen[res+"-cur"] = v, true
			}
			if (side == "" || side == "-max") && !seen[res+"-max"] {
				r.Max, seen[res+"-max"] = v, true
			}
		}
		for _, t := range tcs {
			if err := walk(t, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(class, 0); err != nil {
		return nil, err
	}
	var out []classRlimit
	for _, res := range limitOrder {
		if r := got[res]; r != nil && (r.Cur.Set || r.Max.Set) {
			out = append(out, *r)
		}
	}
	return out, nil
}

// encodeValue is "-" (unset), "inf" or the decimal number.
func encodeValue(v limitValue) string {
	switch {
	case !v.Set:
		return "-"
	case v.Inf:
		return "inf"
	}
	return strconv.FormatUint(v.N, 10)
}

// EncodeLimits renders limits as resource=cur:max,... for the exec stub.
func EncodeLimits(ls []classRlimit) string {
	parts := make([]string, len(ls))
	for i, l := range ls {
		parts[i] = l.Resource + "=" + encodeValue(l.Cur) + ":" + encodeValue(l.Max)
	}
	return strings.Join(parts, ",")
}

func decodeValue(s string) (limitValue, error) {
	switch s {
	case "-":
		return limitValue{}, nil
	case "inf":
		return limitValue{Set: true, Inf: true}, nil
	}
	n, err := strconv.ParseUint(s, 10, 63)
	if err != nil || (len(s) > 1 && s[0] == '0') {
		return limitValue{}, fmt.Errorf("%w: bad value %q", errClassLimit, s)
	}
	return limitValue{Set: true, N: n}, nil
}

// DecodeLimits is the inverse of EncodeLimits; an unknown resource or a bad
// number refuses (the stub then does not exec the program).
func DecodeLimits(s string) ([]classRlimit, error) {
	if s == "" {
		return nil, nil
	}
	var out []classRlimit
	for _, p := range strings.Split(s, ",") {
		res, vals, ok := strings.Cut(p, "=")
		cur, max, ok2 := strings.Cut(vals, ":")
		known := false
		for _, r := range limitOrder {
			known = known || r == res
		}
		if !ok || !ok2 || !known || len(out) >= len(limitOrder) {
			return nil, fmt.Errorf("%w: bad entry %q", errClassLimit, p)
		}
		c, err := decodeValue(cur)
		if err != nil {
			return nil, err
		}
		m, err := decodeValue(max)
		if err != nil {
			return nil, err
		}
		out = append(out, classRlimit{Resource: res, Cur: c, Max: m})
	}
	return out, nil
}

// loginConfDir holds one file per class that takes precedence over the same
// class in login.conf (login.conf(5)).
var loginConfDir = "/etc/login.conf.d"

// validClassName is a class name that cannot name a path.
func validClassName(n string) bool {
	if n == "" || len(n) > 64 || n[0] == '.' {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// LoadClassLimits resolves the limits of class from login.conf and
// login.conf.d. read returns the text of a file, and false if it does not
// exist (a file that exists and cannot be read is an error: the caller judges
// the file, root-owned and not writable by others, before returning it).
func LoadClassLimits(class string, read func(path string) (string, bool, error)) ([]classRlimit, error) {
	if !validClassName(class) {
		return nil, fmt.Errorf("%w: bad class name %q", errClassLimit, class)
	}
	main, ok, err := read(loginConfPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %s does not exist", errClassLimit, loginConfPath)
	}
	mainEntries := loginEntries(main)
	var lookupErr error
	lookup := func(name string) ([]string, bool) {
		if validClassName(name) {
			d, found, err := read(loginConfDir + "/" + name)
			if err != nil {
				lookupErr = err
				return nil, false
			}
			if found {
				if caps, ok := loginEntries(d)[name]; ok {
					return caps, true
				}
			}
		}
		caps, ok := mainEntries[name]
		return caps, ok
	}
	ls, err := ClassLimits(class, lookup)
	if lookupErr != nil {
		return nil, lookupErr
	}
	return ls, err
}
