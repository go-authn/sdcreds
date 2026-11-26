package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

const sampleLoginConf = `# a comment
default:\
	:path=/usr/bin /bin:\
	:umask=022:\
	:datasize-max=1g:\
	:datasize-cur=512M:\
	:maxproc-max=256:\
	:maxproc-cur=128:\
	:openfiles-cur=512:\
	:openfiles-max=1024:\
	:tc=base:

base:\
	:cputime=1h:\
	:openfiles=64:\
	:coredumpsize=0:

daemon|daemon class:\
	:openfiles-cur=2048:\
	:maxproc@:\
	:tc=default:
loop1:tc=loop2:
loop2:tc=loop1:
bad:datasize=lots:
nolim:path=/bin:
`

func limitsOf(t *testing.T, class string) ([]classRlimit, error) {
	t.Helper()
	e := loginEntries(sampleLoginConf)
	return ClassLimits(class, func(n string) ([]string, bool) { c, ok := e[n]; return c, ok })
}

func TestClassLimitsResolveTheTCChain(t *testing.T) {
	got, err := limitsOf(t, "daemon")
	if err != nil {
		t.Fatal(err)
	}
	// daemon wins over default over base; maxproc@ removes the limit from there on;
	// datasize-cur=512M is "512m" in this file's suffix table (not accepted: M
	// reads as m, mebibytes), cputime comes from base.
	want := "cpu=3600:3600,data=536870912:1073741824,core=0:0,nofile=2048:1024"
	if s := EncodeLimits(got); s != want {
		t.Errorf("got  %s\nwant %s", s, want)
	}
}

func TestClassLimitsRefuseWhatTheyCannotRead(t *testing.T) {
	for _, c := range []string{"loop1", "bad", "nosuch"} {
		if _, err := limitsOf(t, c); !errors.Is(err, errClassLimit) {
			t.Errorf("%s: %v", c, err)
		}
	}
	if got, err := limitsOf(t, "nolim"); err != nil || len(got) != 0 {
		t.Errorf("a class without limits: %v %v", got, err)
	}
}

func TestClassLimitsTCDepthIsBounded(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 20; i++ {
		b.WriteString("c" + string(rune('a'+i)) + ":tc=c" + string(rune('a'+i+1)) + ":\n")
	}
	e := loginEntries(b.String())
	_, err := ClassLimits("ca", func(n string) ([]string, bool) { c, ok := e[n]; return c, ok })
	if !errors.Is(err, errClassLimit) || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("a chain of 20: %v", err)
	}
}

func TestParseLimitValue(t *testing.T) {
	for _, c := range []struct {
		res, in string
		want    uint64
		inf     bool
		bad     bool
	}{
		{"data", "10", 10, false, false},
		{"data", "1k", 1024, false, false},
		{"data", "2M", 2 << 20, false, false},
		{"data", "1b", 512, false, false},
		{"cpu", "2m", 120, false, false},
		{"cpu", "1w", 604800, false, false},
		{"data", "infinity", 0, true, false},
		{"data", "unlimited", 0, true, false},
		{"data", "", 0, false, true},
		{"data", "k", 0, false, true},
		{"data", "1x", 0, false, true},
		{"cpu", "1k", 0, false, true},
		{"data", "-1", 0, false, true},
		{"data", "9223372036854775807k", 0, false, true},
		{"data", "99999999999999999999", 0, false, true},
	} {
		v, err := parseLimitValue(c.res, c.in)
		if (err != nil) != c.bad || (!c.bad && (v.N != c.want || v.Inf != c.inf || !v.Set)) {
			t.Errorf("%s %q: %+v %v", c.res, c.in, v, err)
		}
	}
}

func TestLimitsRoundTripAndRefuseJunk(t *testing.T) {
	ls, err := limitsOf(t, "default")
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeLimits(EncodeLimits(ls))
	if err != nil || EncodeLimits(back) != EncodeLimits(ls) {
		t.Errorf("round trip: %v %v", back, err)
	}
	for _, bad := range []string{"cpu", "cpu=1", "cpu=a:b", "nosuch=1:2", "cpu=01:2", "cpu=1:2:3", "cpu=-1:2", "cpu=1:2,"} {
		if _, err := DecodeLimits(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if got, err := DecodeLimits(""); err != nil || got != nil {
		t.Errorf("empty: %v %v", got, err)
	}
	// more entries than resources
	long := strings.TrimSuffix(strings.Repeat("cpu=1:1,", 10), ",")
	if _, err := DecodeLimits(long); err == nil {
		t.Error("accepted 10 entries")
	}
}

func TestLoginEntriesFirstDefinitionWinsAndContinues(t *testing.T) {
	e := loginEntries("a|b:x=1:\\\n\t:y=2:\na:z=3:\n")
	if got := strings.Join(e["b"], ","); got != "x=1,y=2" {
		t.Errorf("b = %q", got)
	}
	if got := strings.Join(e["a"], ","); got != "x=1,y=2" {
		t.Errorf("a = %q (the first definition must win)", got)
	}
}

func TestLoadClassLimitsPrefersTheClassFile(t *testing.T) {
	files := map[string]string{
		loginConfPath:                   "web:openfiles=10:\nother:openfiles=20:tc=web:\n",
		loginConfDir + "/web":           "web:openfiles=30:\n",
		loginConfDir + "/unrelated":     "x:openfiles=1:\n",
		loginConfDir + "/emptyoverride": "nothing:\n",
	}
	read := func(p string) (string, bool, error) { s, ok := files[p]; return s, ok, nil }
	got, err := LoadClassLimits("web", read)
	if err != nil || EncodeLimits(got) != "nofile=30:30" {
		t.Errorf("web: %v %v", EncodeLimits(got), err)
	}
	// a tc= target is looked up in login.conf.d too
	got, err = LoadClassLimits("other", read)
	if err != nil || EncodeLimits(got) != "nofile=20:20" {
		t.Errorf("other: %v %v", EncodeLimits(got), err)
	}
	// a class file that does not define the class is not used
	files[loginConfDir+"/web"] = "bogus:openfiles=99:\n"
	if got, err = LoadClassLimits("web", read); err != nil || EncodeLimits(got) != "nofile=10:10" {
		t.Errorf("a class file without the class: %v %v", EncodeLimits(got), err)
	}
	for _, bad := range []string{"", "../x", ".hidden", "a/b", strings.Repeat("a", 65), "a b"} {
		if _, err := LoadClassLimits(bad, read); !errors.Is(err, errClassLimit) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// read errors are errors, not "no limits"
	boom := errors.New("boom")
	if _, err := LoadClassLimits("web", func(string) (string, bool, error) { return "", false, boom }); !errors.Is(err, boom) {
		t.Errorf("a read error: %v", err)
	}
	failDir := func(p string) (string, bool, error) {
		if strings.HasPrefix(p, loginConfDir) {
			return "", false, boom
		}
		return files[p], true, nil
	}
	if _, err := LoadClassLimits("web", failDir); !errors.Is(err, boom) {
		t.Errorf("a class file read error: %v", err)
	}
	if _, err := LoadClassLimits("web", func(string) (string, bool, error) { return "", false, nil }); !errors.Is(err, errClassLimit) {
		t.Errorf("no login.conf: %v", err)
	}
}

func TestValidClassName(t *testing.T) {
	for _, ok := range []string{"daemon", "a-b_c.d", "A1", strings.Repeat("a", 64)} {
		if !validClassName(ok) {
			t.Errorf("%q refused", ok)
		}
	}
	for _, bad := range []string{"", ".x", "a/b", "a b", "a:b", "a\x00", "é", strings.Repeat("a", 65)} {
		if validClassName(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestLoadClassLimitsReadsNothingForABadNameAndNamesAMissingFile(t *testing.T) {
	reads := 0
	read := func(string) (string, bool, error) { reads++; return "", false, nil }
	if _, err := LoadClassLimits("../x", read); !errors.Is(err, errClassLimit) || reads != 0 {
		t.Errorf("bad name: %v (%d reads)", err, reads)
	}
	if _, err := LoadClassLimits("web", read); !errors.Is(err, errClassLimit) || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing login.conf: %v", err)
	}
}

func TestClassLimitsNameATCLoop(t *testing.T) {
	if _, err := limitsOf(t, "loop1"); err == nil || !strings.Contains(err.Error(), "loop") {
		t.Errorf("a loop must be named as one: %v", err)
	}
}

func TestCheckClassAcceptsOnlyARegularClassFile(t *testing.T) {
	oldDir, oldConf := loginConfDir, loginConfPath
	t.Cleanup(func() { loginConfDir, loginConfPath = oldDir, oldConf })
	loginConfDir, loginConfPath = t.TempDir(), t.TempDir()+"/absent"
	if err := os.WriteFile(loginConfDir+"/file", nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(loginConfDir+"/dir", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkClass("file"); err != nil {
		t.Errorf("a class file: %v", err)
	}
	if err := checkClass("dir"); err == nil {
		t.Error("a directory is not a class file")
	}
}
