package main

import (
	"errors"
	"slices"
	"testing"
)

func knownResource(r string) bool { return slices.Contains(limitOrder, r) }

// checkLimits is what every decoded or loaded set of limits must satisfy: known
// resources only, a bounded count, and an encoding that decodes to the same set.
func checkLimits(t *testing.T, what string, ls []classRlimit) {
	t.Helper()
	if len(ls) > len(limitOrder) {
		t.Fatalf("%s: %d limits, at most %d", what, len(ls), len(limitOrder))
	}
	for _, l := range ls {
		if !knownResource(l.Resource) {
			t.Fatalf("%s: unknown resource %q", what, l.Resource)
		}
		for _, v := range []limitValue{l.Cur, l.Max} {
			if !v.Set && (v.Inf || v.N != 0) {
				t.Fatalf("%s: an unset value carries data: %+v", what, v)
			}
			if v.Inf && v.N != 0 {
				t.Fatalf("%s: infinity carries a number: %+v", what, v)
			}
			if v.N >= 1<<63 {
				t.Fatalf("%s: value %d out of range", what, v.N)
			}
		}
	}
	back, err := DecodeLimits(EncodeLimits(ls))
	if err != nil {
		t.Fatalf("%s: the encoding %q does not decode: %v", what, EncodeLimits(ls), err)
	}
	if !slices.Equal(back, ls) && !(len(back) == 0 && len(ls) == 0) {
		t.Fatalf("%s: %+v encodes to %q and decodes to %+v", what, ls, EncodeLimits(ls), back)
	}
}

// FuzzDecodeLimits: the exec stub decodes what it is handed through the
// environment; whatever it is, no panic, and an accepted value is well formed.
func FuzzDecodeLimits(f *testing.F) {
	for _, s := range []string{
		"", "nofile=64:128", "core=-:inf", "cpu=inf:inf,data=1:2", "nofile=", "nofile=1", "=:", "nofile=01:2",
		"nofile=9223372036854775808:1", "bogus=1:2", "nofile=1:2,", ",", "nofile=1:2,nofile=3:4", "=", "a=b:c",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ls, err := DecodeLimits(in)
		if err != nil {
			if !errors.Is(err, errClassLimit) {
				t.Fatalf("%q: an error that is not errClassLimit: %v", in, err)
			}
			return
		}
		checkLimits(t, in, ls)
	})
}

// FuzzLoadClassLimits: login.conf and its drop-in are text anyone could have
// shaped (a class loop, a huge capability, a name that is a path); the answer is
// an error or well-formed limits, after a bounded number of reads.
func FuzzLoadClassLimits(f *testing.F) {
	for _, s := range [][3]string{
		{"svc", "svc:\\\n\t:openfiles=64:\n", ""},
		{"svc", "default:\\\n\t:openfiles-cur=10:\n", "svc:\\\n\t:tc=default:\n"},
		{"a", "a:tc=b:\nb:tc=a:\n", ""},
		{"a", "a:tc=a:\n", ""},
		{"a", "a:cputime=infinity:datasize=1g:\n", "a:stacksize-max=2m:\n"},
		{"a", "a:openfiles=99999999999999999999:\n", ""},
		{"../x", "x:\n", ""},
		{"", "", ""},
	} {
		f.Add(s[0], s[1], s[2])
	}
	f.Fuzz(func(t *testing.T, class, conf, dropin string) {
		reads := 0
		read := func(path string) (string, bool, error) {
			reads++
			if reads > 10000 {
				t.Fatalf("%d reads: a class loop that nothing stops", reads)
			}
			switch path {
			case loginConfPath:
				return conf, true, nil
			case loginConfDir + "/" + class:
				if dropin != "" {
					return dropin, true, nil
				}
			}
			return "", false, nil
		}
		ls, err := LoadClassLimits(class, read)
		if err != nil {
			return
		}
		checkLimits(t, class, ls)
	})
}
