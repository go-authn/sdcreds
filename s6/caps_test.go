package s6

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestCapNamesMatchTheKernelNumbers(t *testing.T) {
	// linux/capability.h: the last capability is CAP_CHECKPOINT_RESTORE, 40.
	if len(capNames) != 41 || capNames[0] != "CAP_CHOWN" || capNames[40] != "CAP_CHECKPOINT_RESTORE" {
		t.Fatalf("%d names, %s .. %s", len(capNames), capNames[0], capNames[len(capNames)-1])
	}
	for c, want := range map[Cap]string{
		CapNetBindService: "CAP_NET_BIND_SERVICE", CapNetBroadcast: "CAP_NET_BROADCAST", CapNetAdmin: "CAP_NET_ADMIN",
		CapNetRaw: "CAP_NET_RAW", CapIPCLock: "CAP_IPC_LOCK", CapWakeAlarm: "CAP_WAKE_ALARM", CapBlockSuspend: "CAP_BLOCK_SUSPEND",
		7: "CAP_SETUID", 21: "CAP_SYS_ADMIN",
	} {
		if c.String() != want {
			t.Errorf("%d is %s, want %s", int(c), c, want)
		}
	}
	if Cap(41).String() != "CAP_41" || Cap(-1).String() != "CAP_-1" {
		t.Errorf("%s %s", Cap(41), Cap(-1))
	}
}

func TestAllowlist(t *testing.T) {
	want := []string{"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW", "CAP_NET_BROADCAST", "CAP_IPC_LOCK", "CAP_WAKE_ALARM", "CAP_BLOCK_SUSPEND"}
	if got := allowlist(); got != strings.Join(want, ", ") {
		t.Errorf("%s", got)
	}
	// Exactly these seven are accepted, of all 41 known capabilities.
	for c := Cap(0); c < 41; c++ {
		err := CheckKeepCaps([]Cap{c})
		if allowed := slices.Contains(want, c.String()); allowed != (err == nil) {
			t.Errorf("%v: allowed=%v, error=%v", c, allowed, err)
		}
		if err != nil && (!strings.Contains(err.Error(), c.String()) || !strings.Contains(err.Error(), "the allowlist is "+strings.Join(want, ", "))) {
			t.Errorf("%v: %v", c, err)
		}
	}
	if err := CheckKeepCaps(nil); err != nil {
		t.Errorf("none: %v", err)
	}
	// One bad entry among good ones is refused.
	if err := CheckKeepCaps([]Cap{CapNetAdmin, 21}); err == nil || !strings.Contains(err.Error(), "CAP_SYS_ADMIN") {
		t.Errorf("%v", err)
	}
}

func TestParseKeepCaps(t *testing.T) {
	for name, tc := range map[string]struct {
		in   []string
		want []Cap
	}{
		"nothing":            {nil, nil},
		"one":                {[]string{"CAP_NET_ADMIN"}, []Cap{CapNetAdmin}},
		"comma":              {[]string{"CAP_NET_ADMIN,CAP_NET_RAW"}, []Cap{CapNetAdmin, CapNetRaw}},
		"repeated":           {[]string{"CAP_NET_RAW", "CAP_NET_ADMIN"}, []Cap{CapNetAdmin, CapNetRaw}},
		"both, with blanks":  {[]string{" CAP_NET_RAW , CAP_IPC_LOCK", "CAP_NET_ADMIN"}, []Cap{CapNetAdmin, CapNetRaw, CapIPCLock}},
		"duplicates":         {[]string{"CAP_NET_ADMIN,CAP_NET_ADMIN", "CAP_NET_ADMIN"}, []Cap{CapNetAdmin}},
		"lower case":         {[]string{"cap_net_admin"}, []Cap{CapNetAdmin}},
		"all seven, sorted":  {[]string{"CAP_BLOCK_SUSPEND,CAP_WAKE_ALARM,CAP_IPC_LOCK,CAP_NET_RAW,CAP_NET_BROADCAST,CAP_NET_ADMIN,CAP_NET_BIND_SERVICE"}, []Cap{10, 11, 12, 13, 14, 35, 36}},
		"empty value is nil": {[]string{}, nil},
	} {
		got, err := ParseKeepCaps(tc.in)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %v, %v; want %v", name, got, err, tc.want)
		}
	}
}

func TestParseKeepCapsRefusals(t *testing.T) {
	list := "the allowlist is CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_NET_BROADCAST, CAP_IPC_LOCK, CAP_WAKE_ALARM, CAP_BLOCK_SUSPEND"
	for name, tc := range map[string]struct {
		in   []string
		part string // what the message must say besides the allowlist
	}{
		"known but not allowed":     {[]string{"CAP_SYS_ADMIN"}, "CAP_SYS_ADMIN may not be kept"},
		"root equivalent":           {[]string{"CAP_SETUID"}, "CAP_SETUID may not be kept"},
		"reads the credentials":     {[]string{"CAP_DAC_OVERRIDE"}, "CAP_DAC_OVERRIDE may not be kept"},
		"signals root":              {[]string{"CAP_KILL"}, "CAP_KILL may not be kept"},
		"allowed then forbidden":    {[]string{"CAP_NET_ADMIN,CAP_SYS_PTRACE"}, "CAP_SYS_PTRACE may not be kept"},
		"unknown":                   {[]string{"CAP_NET_ADMON"}, `"CAP_NET_ADMON" is not a capability`},
		"short name":                {[]string{"NET_ADMIN"}, `"NET_ADMIN" is not a capability`},
		"a number":                  {[]string{"12"}, `"12" is not a capability`},
		"empty element":             {[]string{"CAP_NET_ADMIN,,CAP_NET_RAW"}, `"" is not a capability`},
		"empty value":               {[]string{""}, `"" is not a capability`},
		"trailing comma":            {[]string{"CAP_NET_ADMIN,"}, `"" is not a capability`},
		"unknown after good repeat": {[]string{"CAP_NET_ADMIN", "CAP_BOGUS"}, `"CAP_BOGUS" is not a capability`},
	} {
		got, err := ParseKeepCaps(tc.in)
		if err == nil || got != nil || !strings.Contains(err.Error(), tc.part) || !strings.Contains(err.Error(), list) {
			t.Errorf("%s: %v, %v", name, got, err)
		}
	}
}

// A forbidden capability is refused before the user is looked up, anything is
// decrypted, or anything is mounted.
func TestRunRefusesAForbiddenCapabilityFirst(t *testing.T) {
	r, c := newRig(t), config(t)
	decrypted := false
	c.Decrypt = func(name string, enc []byte) ([]byte, error) { decrypted = true; return nullDecrypt(name, enc) }
	c.KeepCaps = []Cap{CapNetAdmin, 21}
	err := Run(c, r.ops())
	if err == nil || !strings.Contains(err.Error(), "CAP_SYS_ADMIN may not be kept") || !strings.Contains(err.Error(), "the allowlist is") {
		t.Fatalf("%v", err)
	}
	if len(r.calls) != 0 || decrypted {
		t.Errorf("went on: %v decrypted=%v", r.calls, decrypted)
	}
}

// The kept set reaches Start, and with none given Start sees no capability.
func TestRunHandsTheKeptSetToStart(t *testing.T) {
	for _, keep := range [][]Cap{nil, {CapNetAdmin}, {CapNetAdmin, CapIPCLock}} {
		r, c := newRig(t), config(t)
		ops := r.ops()
		var got []Cap
		start := ops.Start
		ops.Start = func(u User, argv, env []string) (func() (int, error), error) {
			got = u.Keep
			return start(u, argv, env)
		}
		c.KeepCaps = keep
		_ = Run(c, ops)
		if !slices.Equal(got, keep) || (len(keep) == 0 && len(got) != 0) {
			t.Errorf("keep %v: Start saw %v", keep, got)
		}
	}
}
