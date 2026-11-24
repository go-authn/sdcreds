//go:build linux

package s6

import (
	"errors"
	"slices"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// unsafeSlice is the two-element array that capget and capset take by pointer.
func unsafeSlice(d *unix.CapUserData) []unix.CapUserData { return unsafe.Slice(d, 2) }

// keepRig fakes the kernel for restrictThread: capabilities 0..last exist,
// every call is logged in order, and capget returns marker permitted, effective
// and inheritable sets that capset must be seen to keep or replace.
type keepRig struct {
	log      []string
	dropped  []uintptr
	last     uintptr
	failOn   string
	setData  [2]unix.CapUserData
	setCalls int
	secbits  uintptr
}

func newKeepRig(t *testing.T, last uintptr) *keepRig {
	k := &keepRig{last: last}
	swap(t, &prctlCall, func(opt, arg uintptr) (uintptr, error) {
		switch opt {
		case prSetNoNewPrivs:
			k.log = append(k.log, "nnp")
			if k.failOn == "nnp" {
				return 0, syscall.EPERM
			}
		case prCapbsetRead:
			if arg > k.last {
				return 0, syscall.EINVAL
			}
		case prCapbsetDrop:
			k.log = append(k.log, "drop")
			k.dropped = append(k.dropped, arg)
			if k.failOn == "drop" {
				return 0, syscall.EPERM
			}
		case prSetSecurebits:
			k.log = append(k.log, "securebits")
			k.secbits = arg
			if k.failOn == "securebits" {
				return 0, syscall.EPERM
			}
		default:
			return 0, errors.New("unexpected prctl")
		}
		return 0, nil
	})
	swap(t, &capGet, func(h *unix.CapUserHeader, d *unix.CapUserData) error {
		k.log = append(k.log, "capget")
		if h.Version != unix.LINUX_CAPABILITY_VERSION_3 || h.Pid != 0 {
			t.Errorf("header %+v", *h)
		}
		if k.failOn == "capget" {
			return syscall.EPERM
		}
		ds := unsafeSlice(d)
		ds[0] = unix.CapUserData{Effective: 0xAAAA0001, Permitted: 0xBBBB0002, Inheritable: 0xFFFFFFFF}
		ds[1] = unix.CapUserData{Effective: 0x1F, Permitted: 0x3F, Inheritable: 0xFFFFFFFF}
		return nil
	})
	swap(t, &capSet, func(h *unix.CapUserHeader, d *unix.CapUserData) error {
		k.log = append(k.log, "capset")
		k.setCalls++
		ds := unsafeSlice(d)
		k.setData = [2]unix.CapUserData{ds[0], ds[1]}
		if k.failOn == "capset" {
			return syscall.EPERM
		}
		return nil
	})
	return k
}

func TestRestrictThreadWithoutKeepIsV010(t *testing.T) {
	k := newKeepRig(t, 40)
	if err := restrictThread(nil); err != nil {
		t.Fatal(err)
	}
	want := slices.Repeat([]string{"drop"}, 41)
	if !slices.Equal(k.log, append([]string{"nnp"}, want...)) {
		t.Errorf("calls: %v", k.log)
	}
	for i, c := range k.dropped {
		if c != uintptr(i) {
			t.Fatalf("dropped %v", k.dropped)
		}
	}
	if k.secbits != 0 || k.setCalls != 0 {
		t.Errorf("securebits %d, capset calls %d", k.secbits, k.setCalls)
	}
}

func TestRestrictThreadKeeps(t *testing.T) {
	k := newKeepRig(t, 40)
	if err := restrictThread([]Cap{CapNetAdmin, CapNetRaw, CapBlockSuspend}); err != nil {
		t.Fatal(err)
	}
	// Every capability the kernel has is dropped except the kept ones.
	var want []uintptr
	for c := uintptr(0); c <= 40; c++ {
		if c != 12 && c != 13 && c != 36 {
			want = append(want, c)
		}
	}
	if !slices.Equal(k.dropped, want) {
		t.Errorf("dropped %v, want %v", k.dropped, want)
	}
	// Order: no_new_privs, the bounding set, then the inheritable set, then the
	// locked securebits.
	n := len(want)
	order := append(append([]string{"nnp"}, slices.Repeat([]string{"drop"}, n)...), "capget", "capset", "securebits")
	if !slices.Equal(k.log, order) {
		t.Errorf("calls: %v", k.log)
	}
	// The inheritable set is exactly the kept set; the other sets are as capget gave them.
	if k.setData[0].Inheritable != 1<<12|1<<13 || k.setData[1].Inheritable != 1<<(36-32) {
		t.Errorf("inheritable %#x %#x", k.setData[0].Inheritable, k.setData[1].Inheritable)
	}
	if k.setData[0].Permitted != 0xBBBB0002 || k.setData[0].Effective != 0xAAAA0001 || k.setData[1].Permitted != 0x3F || k.setData[1].Effective != 0x1F {
		t.Errorf("permitted or effective changed: %+v", k.setData)
	}
	// NOROOT | NOROOT_LOCKED | NO_SETUID_FIXUP | NO_SETUID_FIXUP_LOCKED.
	if k.secbits != 0xF {
		t.Errorf("securebits %#x", k.secbits)
	}
}

func TestRestrictThreadKeepFailures(t *testing.T) {
	for _, tc := range []struct {
		failOn, msg string
	}{
		{"nnp", "no_new_privs"},
		{"drop", "capability bounding set"},
		{"capget", "inheritable set"},
		{"capset", "inheritable set"},
		{"securebits", "securebits"},
	} {
		k := newKeepRig(t, 40)
		k.failOn = tc.failOn
		err := restrictThread([]Cap{CapNetAdmin})
		if err == nil || !strings.Contains(err.Error(), tc.msg) || !errors.Is(err, syscall.EPERM) {
			t.Errorf("%s: %v", tc.failOn, err)
		}
		// The failing call is the last one made: nothing follows it.
		if k.log[len(k.log)-1] != tc.failOn {
			t.Errorf("%s: calls went on after the failure: %v", tc.failOn, k.log)
		}
		if tc.failOn != "securebits" && k.secbits != 0 {
			t.Errorf("%s: securebits set to %#x after the failure", tc.failOn, k.secbits)
		}
	}
}

// A kernel older than a capability that was asked for is an error, not a
// silent drop of it from the kept set.
func TestRestrictThreadKeepUnknownToTheKernel(t *testing.T) {
	k := newKeepRig(t, 35) // no CAP_BLOCK_SUSPEND (36)
	err := restrictThread([]Cap{CapNetAdmin, CapBlockSuspend})
	if err == nil || !strings.Contains(err.Error(), "does not know") {
		t.Fatalf("%v", err)
	}
	if slices.Contains(k.log, "securebits") || slices.Contains(k.log, "capset") {
		t.Errorf("went on: %v", k.log)
	}
}
