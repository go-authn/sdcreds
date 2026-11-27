//go:build unix

package delivery

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/sdcreds"
	"golang.org/x/sys/unix"
)

type statT = unix.Stat_t

func okDecrypt(string, []byte) ([]byte, error) { return []byte("x"), nil }

func goodConfig() Config {
	return Config{
		Base: "/var/run/sdcreds", Name: "bridge", UID: 1000, GID: 1000,
		Creds:   []Credential{{"smtp-password", []byte("sealed")}},
		Decrypt: okDecrypt,
		Lock:    &Lock{}, UIDLock: &Lock{}, Executable: "/usr/local/bin/sdcreds",
	}
}

// Every refusal of validate has its own case, and none of them may reach the
// Decrypt function: a counter proves it.
func TestValidateRefusals(t *testing.T) {
	long := strings.Repeat("a", 90)
	cases := []struct {
		name string
		euid int
		edit func(*Config)
		want error
	}{
		{"not root", 1000, func(*Config) {}, ErrNotRoot},
		{"empty service", 0, func(c *Config) { c.Name = "" }, ErrBadName},
		{"dot service", 0, func(c *Config) { c.Name = ".hidden" }, ErrBadName},
		{"slash in service", 0, func(c *Config) { c.Name = "a/b" }, ErrBadName},
		{"relative base", 0, func(c *Config) { c.Base = "run/sdcreds" }, ErrBadBase},
		{"unclean base", 0, func(c *Config) { c.Base = "/var/run/../run" }, ErrBadBase},
		{"root base", 0, func(c *Config) { c.Base = "/" }, ErrBadBase},
		{"path too long for the kernel", 0, func(c *Config) { c.Base = "/" + long }, ErrBadBase},
		{"uid 0", 0, func(c *Config) { c.UID = 0 }, ErrRootTarget},
		{"gid 0", 0, func(c *Config) { c.GID = 0 }, ErrRootTarget},
		{"negative uid", 0, func(c *Config) { c.UID = -1 }, ErrBadID},
		{"negative gid", 0, func(c *Config) { c.GID = -1 }, ErrBadID},
		{"uid that wraps to 0", 0, func(c *Config) { c.UID = 1 << 32 }, ErrBadID},
		{"gid that wraps to 0", 0, func(c *Config) { c.GID = 1 << 32 }, ErrBadID},
		{"uid -1 as the kernel reads it", 0, func(c *Config) { c.UID = 0xFFFFFFFF }, ErrBadID},
		{"gid -1 as the kernel reads it", 0, func(c *Config) { c.GID = 0xFFFFFFFF }, ErrBadID},
		{"supplementary group 0", 0, func(c *Config) { c.Groups = []int{5, 0} }, ErrRootTarget},
		{"supplementary group that wraps", 0, func(c *Config) { c.Groups = []int{1 << 32} }, ErrBadID},
		{"too many groups", 0, func(c *Config) { c.Groups = make([]int, maxGroups+1) }, ErrBadID},
		{"no decrypt", 0, func(c *Config) { c.Decrypt = nil }, ErrNoDecrypt},
		{"too many", 0, func(c *Config) {
			c.Creds = make([]Credential, MaxEntries+1)
			for i := range c.Creds {
				c.Creds[i].Name = "n" + string(rune('a'+i%26)) + strings.Repeat("x", i/26)
			}
		}, ErrTooManyEntry},
		{"bad credential name", 0, func(c *Config) { c.Creds[0].Name = "a/b" }, ErrBadName},
		{"empty credential name", 0, func(c *Config) { c.Creds[0].Name = "" }, ErrBadName},
		{"duplicate", 0, func(c *Config) { c.Creds = append(c.Creds, c.Creds[0]) }, ErrDuplicate},
		{"one sealed file too large", 0, func(c *Config) {
			c.Creds[0].Sealed = make([]byte, maxArmoured+1)
		}, sdcreds.ErrTooLarge},
		{"sealed forms together too large", 0, func(c *Config) {
			c.Creds = nil
			for i := 0; i < 40; i++ {
				c.Creds = append(c.Creds, Credential{"c" + string(rune('a'+i%26)) + string(rune('a'+i/26)), make([]byte, maxArmoured)})
			}
		}, sdcreds.ErrTooLarge},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := goodConfig()
			c.Decrypt = func(string, []byte) ([]byte, error) { calls++; return nil, nil }
			tc.edit(&c)
			if tc.want == ErrNoDecrypt {
				c.Decrypt = nil
			}
			err := validate(c, tc.euid)
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
			if calls != 0 {
				t.Fatal("Decrypt was called by a refusal")
			}
		})
	}
	if err := validate(goodConfig(), 0); err != nil {
		t.Fatalf("a good configuration is refused: %v", err)
	}
	c := goodConfig()
	c.Name = strings.Repeat("a", 89-len("/var/run/sdcreds/"))
	if err := validate(c, 0); err != nil {
		t.Fatalf("a path of exactly %d bytes is refused: %v", maxDirLen, err)
	}
}

func TestPrepareRefusesBeforeAnythingHappens(t *testing.T) {
	c := goodConfig()
	c.UID = 0
	calls := 0
	c.Decrypt = func(string, []byte) ([]byte, error) { calls++; return nil, nil }
	if _, err := Prepare(context.Background(), c); err == nil {
		t.Fatal("no refusal")
	}
	if calls != 0 {
		t.Fatal("decrypted before refusing")
	}
}

func TestDecryptAll(t *testing.T) {
	c := goodConfig()
	c.Creds = []Credential{{"a", nil}, {"b", nil}}
	boom := errors.New("boom")
	var got [][]byte
	c.Decrypt = func(name string, _ []byte) ([]byte, error) {
		if name == "b" {
			return nil, boom
		}
		b := []byte("secret")
		got = append(got, b)
		return b, nil
	}
	if _, _, err := decryptAll(c); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
	if string(got[0]) == "secret" {
		t.Fatal("the plaintext decrypted before the failure was not wiped")
	}
	c.Decrypt = func(string, []byte) ([]byte, error) { return make([]byte, MaxTotal/2+1), nil }
	if _, _, err := decryptAll(c); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Fatalf("total over the cap: got %v", err)
	}
	c.Decrypt = func(string, []byte) ([]byte, error) { return []byte("ab"), nil }
	pts, n, err := decryptAll(c)
	if err != nil || n != 4 || len(pts) != 2 {
		t.Fatalf("%v %d %d", err, n, len(pts))
	}
}

func TestNilDeliveryIsSafe(t *testing.T) {
	// Release and Lost of nil are asserted in TestNilDeliveryAndLockAreSafe,
	// which reports a crash as a failed assertion instead of ending the binary.
	var d *Delivery
	if err := d.GuardGroup(5); err == nil {
		t.Fatal("GuardGroup of nil")
	}
}

func TestParseCtl(t *testing.T) {
	good := map[string]Ctl{
		"ready":           {Kind: CtlReady},
		"ok":              {Kind: CtlOK},
		"release":         {Kind: CtlRelease},
		"fail it died":    {Kind: CtlFail, Text: "it died"},
		"pgid 2":          {Kind: CtlPGID, PGID: 2},
		"pgid 123":        {Kind: CtlPGID, PGID: 123},
		"pgid 2147483647": {Kind: CtlPGID, PGID: 2147483647},
	}
	for in, want := range good {
		got, err := ParseCtl(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v", in, got, err)
		}
		if got.String() != in {
			t.Errorf("%q: String gives %q", in, got.String())
		}
	}
	bad := []string{
		"", "READY", "ready ", " ready", "ok\x00", "pgid", "pgid ", "pgid 0", "pgid 1", "pgid -1", "pgid +5",
		"pgid 05", "pgid 2147483648", "pgid 99999999999", "pgid 12a", "pgid  12", "release now", "fail\x01x",
		"fail \xff", strings.Repeat("a", maxCtlLine+1), "pgid 1 2", "nope",
	}
	for _, in := range bad {
		if _, err := ParseCtl(in); !errors.Is(err, ErrCtl) {
			t.Errorf("%q accepted: %v", in, err)
		}
	}
	if _, err := ParseCtl(strings.Repeat("a", maxCtlLine)); !errors.Is(err, ErrCtl) {
		t.Error("an unknown line of the maximal length")
	}
	if _, err := ParseCtl("fail " + strings.Repeat("a", maxCtlLine-5)); err != nil {
		t.Errorf("a fail line of exactly the maximal length: %v", err)
	}
}

func TestCtlSanitize(t *testing.T) {
	s := Ctl{Kind: CtlFail, Text: "a\nb\x00\xffc" + strings.Repeat("z", 1000)}.String()
	if len(s) >= maxCtlLine {
		t.Fatalf("%d bytes", len(s))
	}
	if _, err := ParseCtl(s); err != nil {
		t.Fatalf("a sanitised line does not parse: %v", err)
	}
	if !strings.HasPrefix(s, "fail a?b??c") {
		t.Fatalf("%q", s)
	}
	if (Ctl{}).String() != "" {
		t.Fatal("zero Ctl")
	}
}

func TestReadCtl(t *testing.T) {
	r := bufio.NewReader(strings.NewReader("pgid 7\nready\n" + strings.Repeat("a", 5000) + "\nok\n"))
	if c, err := readCtl(r); err != nil || c.PGID != 7 {
		t.Fatal(c, err)
	}
	if c, err := readCtl(r); err != nil || c.Kind != CtlReady {
		t.Fatal(c, err)
	}
	if _, err := readCtl(r); !errors.Is(err, ErrCtl) {
		t.Fatalf("a line of 5000 bytes: %v", err)
	}
	// An unterminated tail is an error, not a message.
	r = bufio.NewReader(strings.NewReader("ready"))
	if _, err := readCtl(r); err == nil {
		t.Fatal("unterminated line accepted")
	}
	r = bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 4000)), 16)
	if _, err := readCtl(r); err == nil {
		t.Fatal("a long unterminated line accepted")
	}
}

func FuzzParseCtl(f *testing.F) {
	for _, s := range []string{"ready", "ok", "release", "fail x", "pgid 2", "pgid 0", "pgid 05", "", "pgid 99999999999", "\x00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ParseCtl(s)
		if err != nil {
			return
		}
		if c.Kind == CtlPGID && (c.PGID < 2 || c.PGID > 1<<31-1) {
			t.Fatalf("group %d accepted from %q", c.PGID, s)
		}
		if c.Kind != CtlFail {
			if c.String() != s {
				t.Fatalf("%q round trips to %q", s, c.String())
			}
		}
		if _, err := ParseCtl(c.String()); err != nil {
			t.Fatalf("%q: its own output is refused: %v", s, err)
		}
	})
}

func TestValidServiceAndLockPath(t *testing.T) {
	for _, s := range []string{"a", "0", "authn-bridge", "a_b", strings.Repeat("a", 64)} {
		if !ValidService(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", ".a", "-a", "_a", "A", "a b", "a/b", "a\n", "../x", strings.Repeat("a", 65), "é"} {
		if ValidService(s) {
			t.Errorf("%q accepted", s)
		}
	}
	p, err := LockPath("/var/run/sdcreds", "x")
	if err != nil || p != "/var/run/sdcreds/.x.lock" {
		t.Fatal(p, err)
	}
	if _, err := LockPath("/b", "../x"); !errors.Is(err, ErrBadService) {
		t.Fatal(err)
	}
}

func FuzzLockPath(f *testing.F) {
	for _, s := range []string{"a", "", "../x", "a/b", ".a"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p, err := LockPath("/base", s)
		if err != nil {
			return
		}
		if filepath.Dir(p) != "/base" || !strings.HasPrefix(filepath.Base(p), ".") || strings.Contains(s, "/") {
			t.Fatalf("%q gives %q", s, p)
		}
	})
}

func TestParseHelperArgs(t *testing.T) {
	good := helperArgs{Owner: 42, Dir: "/var/run/sdcreds/x", MiB: 4, UID: 1000, GID: 1000, Groups: []int{1000, 77}, Exe: "/usr/local/bin/sdcreds"}
	got, err := parseHelperArgs(good.argv())
	if err != nil || !slices.Equal(got.Groups, good.Groups) || got.Owner != good.Owner || got.Dir != good.Dir ||
		got.MiB != good.MiB || got.UID != good.UID || got.GID != good.GID || got.Exe != good.Exe {
		t.Fatal(got, err)
	}
	long := "/" + strings.Repeat("a", maxDirLen)
	tail := []string{"--uid", "1000", "--gid", "1000", "--groups", "", "--exe", "/usr/local/bin/sdcreds"}
	with := func(head ...string) []string { return append(slices.Clone(head), tail...) }
	bad := [][]string{
		nil,
		{"--owner", "42", "--dir", "/a", "--mib"},
		with("--dir", "/a", "--owner", "42", "--mib", "4"),
		with("--owner", "1", "--dir", "/a", "--mib", "4"),
		with("--owner", "0", "--dir", "/a", "--mib", "4"),
		with("--owner", "-5", "--dir", "/a", "--mib", "4"),
		with("--owner", "x", "--dir", "/a", "--mib", "4"),
		with("--owner", "2147483648", "--dir", "/a", "--mib", "4"),
		with("--owner", "42", "--dir", "a", "--mib", "4"),
		with("--owner", "42", "--dir", "/", "--mib", "4"),
		with("--owner", "42", "--dir", "/a/../b", "--mib", "4"),
		with("--owner", "42", "--dir", "/a/", "--mib", "4"),
		with("--owner", "42", "--dir", long, "--mib", "4"),
		with("--owner", "42", "--dir", "/a", "--mib", "3"),
		with("--owner", "42", "--dir", "/a", "--mib", "x"),
		append(with("--owner", "42", "--dir", "/a", "--mib", "4"), "extra"),
		// the old six-word form is not accepted: no target, no executable.
		{"--owner", "42", "--dir", "/a", "--mib", "4"},
	}
	// every field of the tail is judged: ids as 32-bit values that are not root,
	// the executable as an absolute, normalised path.
	head := []string{"--owner", "42", "--dir", "/a", "--mib", "4"}
	for _, tl := range [][]string{
		{"--uid", "0", "--gid", "1000", "--groups", "", "--exe", "/x"},
		{"--uid", "4294967296", "--gid", "1000", "--groups", "", "--exe", "/x"},
		{"--uid", "4294967295", "--gid", "1000", "--groups", "", "--exe", "/x"},
		{"--uid", "01", "--gid", "1000", "--groups", "", "--exe", "/x"},
		{"--uid", "1000", "--gid", "0", "--groups", "", "--exe", "/x"},
		{"--uid", "1000", "--gid", "4294967296", "--groups", "", "--exe", "/x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "0", "--exe", "/x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "5,0", "--exe", "/x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "5,", "--exe", "/x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17", "--exe", "/x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "", "--exe", "x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "", "--exe", "/a/../x"},
		{"--uid", "1000", "--gid", "1000", "--groups", "", "--exe", ""},
		{"--uid", "1000", "--gid", "1000", "--groups", "", "--exe", "/" + strings.Repeat("a", maxExeLen)},
	} {
		bad = append(bad, append(slices.Clone(head), tl...))
	}
	for _, argv := range bad {
		if _, err := parseHelperArgs(argv); err == nil {
			t.Errorf("%q accepted", argv)
		}
	}
}

func FuzzParseHelperArgs(f *testing.F) {
	f.Add("42", "/var/run/x", "4", "1000", "1000", "5,6", "/usr/bin/x")
	f.Add("1", "/", "0", "0", "0", "0", "x")
	f.Fuzz(func(t *testing.T, o, d, m, u, g, gs, e string) {
		a, err := parseHelperArgs([]string{"--owner", o, "--dir", d, "--mib", m, "--uid", u, "--gid", g, "--groups", gs, "--exe", e})
		if err != nil {
			return
		}
		if a.Owner < 2 || !filepath.IsAbs(a.Dir) || filepath.Clean(a.Dir) != a.Dir || len(a.Dir) > maxDirLen {
			t.Fatalf("accepted %+v", a)
		}
		if _, ok := classByMiB(a.MiB); !ok {
			t.Fatalf("accepted size %d", a.MiB)
		}
		// the ids are the ones the kernel would receive, and none is root.
		for _, id := range append([]int{a.UID, a.GID}, a.Groups...) {
			if id < 1 || id >= 0xFFFFFFFF {
				t.Fatalf("accepted id %d in %+v", id, a)
			}
		}
		if len(a.Groups) > maxGroups || !filepath.IsAbs(a.Exe) || filepath.Clean(a.Exe) != a.Exe || len(a.Exe) > maxExeLen {
			t.Fatalf("accepted %+v", a)
		}
	})
}

func TestPickClass(t *testing.T) {
	small, err := pickClass([]string{"a"}, []int{10})
	if err != nil || small.MiB != 1 {
		t.Fatal(small, err)
	}
	// 600 KiB does not fit a 1 MiB image with its 10 % margin, 2 MiB does.
	c, err := pickClass([]string{"a"}, []int{800 * 1024})
	if err != nil || c.MiB != 2 {
		t.Fatalf("%v %v", c, err)
	}
	// Many tiny files are bound by inodes, not by bytes.
	names := make([]string, 600)
	sizes := make([]int, 600)
	for i := range names {
		names[i] = "n" + strings.Repeat("x", i%7)
		sizes[i] = 1
	}
	c, err = pickClass(names, sizes) // 600 blocks of 4 KiB is 2.4 MB with margin
	if err != nil || c.MiB != 4 {
		t.Fatalf("600 files: %v %v", c, err)
	}
	if _, err := pickClass([]string{"big"}, []int{64 << 20}); !errors.Is(err, ErrTooManyEntry) {
		t.Fatalf("too big: %v", err)
	}
	// A file past the 12 direct blocks costs an indirect block more.
	kb, _ := need([]string{"a"}, []int{13 * fsBlock})
	kb0, _ := need([]string{"a"}, []int{12 * fsBlock})
	if kb-kb0 < 2*fsBlock/1024 {
		t.Fatalf("no indirect block counted: %d vs %d", kb, kb0)
	}
	if _, ok := classByMiB(3); ok {
		t.Fatal("class 3")
	}
	for _, cl := range classes {
		if cl.DataKB >= cl.MiB*1024 {
			t.Fatalf("class %d claims more than its size", cl.MiB)
		}
	}
}

func fakeTrust(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	oldU, oldA := trustedUID, ancestorsFrom
	trustedUID, ancestorsFrom = uint32(os.Getuid()), root
	t.Cleanup(func() { trustedUID, ancestorsFrom = oldU, oldA })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestEnsureBase(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	base := filepath.Join(root, "var", "run", "sdcreds")
	if err := EnsureBase(base); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(base)
	if err != nil || st.Mode().Perm() != 0o711 {
		t.Fatalf("%v %v", st, err)
	}
	if err := EnsureBase(base); err != nil {
		t.Fatal("second call:", err)
	}
	for _, bad := range []string{"relative/x", base + "/../x", base + "/", "", "/"} {
		if bad == "/" {
			continue
		}
		if err := EnsureBase(bad); !errors.Is(err, ErrBadBase) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestEnsureBaseRefusesLinksAndWritableDirs(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBase(filepath.Join(root, "link", "sub")); err == nil {
		t.Fatal("a symbolic link in the path was followed")
	}
	if err := os.Symlink(filepath.Join(real, "sub"), filepath.Join(real, "leaf")); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBase(filepath.Join(real, "leaf")); err == nil {
		t.Fatal("a symbolic link as the base was followed")
	}
	for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
		if err := os.Chmod(filepath.Join(real, "sub"), mode); err != nil {
			t.Fatal(err)
		}
		if err := EnsureBase(filepath.Join(real, "sub")); !errors.Is(err, ErrUntrustedPath) {
			t.Errorf("mode %o: %v", mode, err)
		}
	}
	if err := os.Chmod(filepath.Join(real, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(real, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := EnsureBase(filepath.Join(real, "sub")); !errors.Is(err, ErrUntrustedPath) {
		t.Errorf("a group-writable ancestor: %v", err)
	}
	if err := os.Chmod(real, 0o755); err != nil {
		t.Fatal(err)
	}
	trustedUID++
	if err := EnsureBase(filepath.Join(real, "sub")); !errors.Is(err, ErrUntrustedPath) {
		t.Errorf("a foreign owner: %v", err)
	}
}

func TestEnsureBaseSyscallFailures(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	base := filepath.Join(root, "b")
	boom := errors.New("boom")
	oldO, oldF, oldM := openat, fstat, mkdirat
	defer func() { openat, fstat, mkdirat = oldO, oldF, oldM }()
	mkdirat = func(int, string, uint32) error { return boom }
	if err := EnsureBase(base); err == nil {
		t.Fatal("mkdir failure ignored")
	}
	mkdirat = oldM
	n := 0
	openat = func(fd int, p string, flags int, mode uint32) (int, error) {
		n++
		if n == 1 {
			return oldO(fd, p, flags, mode)
		}
		return -1, boom
	}
	if err := EnsureBase(base); !errors.Is(err, boom) {
		t.Fatalf("openat failure: %v", err)
	}
	openat = func(int, string, int, uint32) (int, error) { return -1, boom }
	if err := EnsureBase(base); !errors.Is(err, boom) {
		t.Fatalf("root open failure: %v", err)
	}
	openat = oldO
	fstat = func(int, *statT) error { return boom }
	if err := EnsureBase(base); !errors.Is(err, boom) {
		t.Fatalf("fstat failure: %v", err)
	}
}

func TestAcquireLock(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	l, err := AcquireLock(root, "svc")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(root, "svc"); !errors.Is(err, ErrBusy) {
		t.Fatalf("second lock: %v", err)
	}
	other, err := AcquireLock(root, "other")
	if err != nil {
		t.Fatalf("another service must not be blocked: %v", err)
	}
	other.Close()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal("Close twice:", err)
	}
	// A stale lock file (its owner died) is taken over.
	l, err = AcquireLock(root, "svc")
	if err != nil {
		t.Fatalf("stale lock file: %v", err)
	}
	l.Close()
	var nl *Lock
	if err := nl.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(root, "../x"); !errors.Is(err, ErrBadService) {
		t.Fatal(err)
	}
	if _, err := AcquireLock(filepath.Join(root, "missing"), "svc"); err == nil {
		t.Fatal("lock in a missing directory")
	}
}

// F6: a start waits, bounded, for the lock of a teardown in progress on the same
// service, and still refuses a lock that stays held.
func TestAcquireLockWaitsForATeardown(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	held, err := AcquireLock(root, "svc")
	if err != nil {
		t.Fatal(err)
	}
	// No wait: the old behaviour, refused at once.
	if _, err := AcquireLockWait(root, "svc", 0); !errors.Is(err, ErrBusy) {
		t.Fatalf("no wait: %v", err)
	}
	// Held past the bound: refused, after waiting about the bound.
	t0 := time.Now()
	if _, err := AcquireLockWait(root, "svc", 300*time.Millisecond); !errors.Is(err, ErrBusy) || time.Since(t0) < 250*time.Millisecond {
		t.Fatalf("held past the bound: %v after %v", err, time.Since(t0))
	}
	// Released during the wait: acquired.
	go func() { time.Sleep(200 * time.Millisecond); held.Close() }()
	l, err := AcquireLockWait(root, "svc", 5*time.Second)
	if err != nil {
		t.Fatalf("released during the wait: %v", err)
	}
	l.Close()
	if TeardownWait < 26*time.Second {
		t.Fatalf("TeardownWait %v is shorter than the longest teardown (20 s + 1 s + 5 s)", TeardownWait)
	}
	// The user lock follows the same rule, and is for ONE service: held, it is
	// refused after the grace.
	u, err := AcquireUIDLock(root, 32011)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if _, err := AcquireUIDLockWait(root, 32011, 100*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("user lock held: %v", err)
	}
}

// An error other than ErrBusy is not waited on.
func TestWaitForReturnsOtherErrorsAtOnce(t *testing.T) {
	boom := errors.New("boom")
	calls := 0
	t0 := time.Now()
	if _, err := waitFor(5*time.Second, func() (*Lock, error) { calls++; return nil, boom }); err != boom || calls != 1 || time.Since(t0) > time.Second {
		t.Fatalf("err %v calls %d after %v", err, calls, time.Since(t0))
	}
}

// A wait that never succeeds ends at its bound, with the last error; a loop
// that did not end would stop the suite, so it is cut short here.
func TestWaitForEndsAtItsBound(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, err := waitFor(150*time.Millisecond, func() (*Lock, error) { return nil, ErrBusy })
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrBusy) {
			t.Fatalf("err %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the wait did not end at its bound")
	}
}

func TestAcquireLockRefusesUntrustedFiles(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("owner checks need an unprivileged user")
	}
	root := fakeTrust(t)
	p, _ := LockPath(root, "svc")
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := AcquireLock(root, "svc"); !errors.Is(err, ErrUntrustedPath) {
			t.Errorf("mode %o: %v", mode, err)
		}
		os.Remove(p)
	}
	// A symbolic link is not followed.
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(root, "svc"); err == nil {
		t.Fatal("a symbolic link as the lock file")
	}
	os.Remove(p)
	// A hard link (two names) is refused.
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(p, filepath.Join(root, "second")); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(root, "svc"); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("hard link: %v", err)
	}
	os.Remove(p)
	// A directory in its place.
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(root, "svc"); err == nil {
		t.Fatal("a directory as the lock file")
	}
	os.Remove(p)
	// A foreign owner.
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	trustedUID++
	if _, err := AcquireLock(root, "svc"); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("foreign owner: %v", err)
	}
}
