package s6

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-authn/sdcreds"
)

// R6: when the caller reads the source, load decrypts what it was given, with
// the same refusals, and does not look at the directory itself.
func TestLoadFromAReadSource(t *testing.T) {
	c := config(t)
	c.Source = "/nonexistent-never-read"
	boom := errors.New("untrusted")
	c.ReadSource = func(dir string) ([]Sealed, error) {
		if dir != c.Source {
			t.Fatalf("read %q", dir)
		}
		return nil, boom
	}
	if _, err := load(c); !errors.Is(err, boom) {
		t.Fatalf("a refused source: %v", err)
	}
	enc := func(name, secret string) []byte {
		blob, err := sdcreds.Encrypt([]byte(secret), sdcreds.EncryptOptions{Key: sdcreds.IDNull, Name: name, Timestamp: 1})
		if err != nil {
			t.Fatal(err)
		}
		return []byte(sdcreds.Armor(blob, 79))
	}
	c.ReadSource = func(string) ([]Sealed, error) {
		return []Sealed{{"a", enc("a", "one")}, {"b", enc("b", "two")}}, nil
	}
	es, err := load(c)
	if err != nil || len(es) != 2 || string(es[0].data) != "one" || es[1].name != "b" || string(es[1].data) != "two" {
		t.Fatalf("%v %v", es, err)
	}
	good := c.Decrypt
	// A decrypter that accepts anything, so only the name check can refuse.
	c.Decrypt = func(string, []byte) ([]byte, error) { return []byte("x"), nil }
	c.ReadSource = func(string) ([]Sealed, error) { return []Sealed{{"../x", enc("a", "one")}}, nil }
	if _, err := load(c); err == nil {
		t.Fatal("a bad name was accepted")
	}
	c.Decrypt = good
	c.ReadSource = func(string) ([]Sealed, error) { return []Sealed{{"a", enc("a", "one")}}, nil }
	c.Decrypt = func(string, []byte) ([]byte, error) { return nil, boom }
	if _, err := load(c); !errors.Is(err, boom) {
		t.Fatalf("a credential that does not decrypt: %v", err)
	}
	c.Decrypt = good
	many := make([]Sealed, MaxEntries+1)
	for i := range many {
		many[i] = Sealed{fmt.Sprintf("f%d", i), enc(fmt.Sprintf("f%d", i), "x")}
	}
	c.ReadSource = func(string) ([]Sealed, error) { return many, nil }
	if _, err := load(c); err == nil {
		t.Fatal("too many entries")
	}
	c.ReadSource = func(string) ([]Sealed, error) { return []Sealed{{"big", enc("big", "x")}}, nil }
	c.Decrypt = func(string, []byte) ([]byte, error) { return make([]byte, MaxTotal+1), nil }
	if _, err := load(c); !errors.Is(err, sdcreds.ErrTooLarge) {
		t.Fatalf("too much: %v", err)
	}
}

// assertNoCrash runs f and fails the test, by an assertion, when f panics: a
// guard that is deleted must show as a wrong value, not as a crash of the whole
// test binary that hides every other assertion.
func assertNoCrash(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("crashed instead of refusing: %v", r)
		}
	}()
	f()
}

// A Config without ReadSource is refused with ErrNoReadSource and no entries,
// and one with a ReadSource is not: the guard is held on both sides, by values.
func TestLoadRefusesAConfigWithoutAReadSource(t *testing.T) {
	c := config(t)
	c.ReadSource = nil
	var es []entry
	var err error
	assertNoCrash(t, func() { es, err = load(c) })
	if !errors.Is(err, ErrNoReadSource) || es != nil {
		t.Fatalf("no ReadSource: entries %v, err %v", es, err)
	}

	called := false
	c.ReadSource = func(string) ([]Sealed, error) { called = true; return nil, nil }
	assertNoCrash(t, func() { es, err = load(c) })
	if err != nil || len(es) != 0 || !called {
		t.Fatalf("an empty source: entries %v, err %v, read %v", es, err, called)
	}
}
