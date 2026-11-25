//go:build !openbsd

package delivery

import (
	"context"
	"errors"
	"os"
)

type state struct{ lost chan struct{} }

func prepare(ctx context.Context, c Config) (*Delivery, error) { return nil, ErrUnsupported }

// release reads d like the OpenBSD one does, so a Release that lost its nil
// check fails here as it would there.
func (d *Delivery) release() error { _ = d.Dir; return nil }

func (d *Delivery) guardGroup(pgid int) error { return ErrUnsupported }

// ServeMFS reports ErrUnsupported off OpenBSD.
func ServeMFS(argv []string, ctl *os.File) error { return ErrUnsupported }

// KillTarget reports ErrUnsupported off OpenBSD.
func (d *Delivery) KillTarget() error { return ErrUnsupported }

// KillCommand is the hidden command that kills every process of the target
// user; off OpenBSD it does nothing (and kill(-1) is never made).
const KillCommand = "__sdcreds-killuid"

// KillMain refuses off OpenBSD.
func KillMain(args []string) int { return 64 }

// ErrUIDBusy and ErrUIDSurvives exist for the callers on every system.
var (
	ErrUIDBusy     = errors.New("delivery: the target user already has processes")
	ErrUIDSurvives = errors.New("delivery: processes of the target user survived SIGKILL")
)

// UIDBusy reports ErrUnsupported off OpenBSD.
func UIDBusy(exe string, uid, gid int, groups []int) (bool, error) { return false, ErrUnsupported }

// KillUID reports ErrUnsupported off OpenBSD.
func KillUID(exe string, uid, gid int, groups []int) error { return ErrUnsupported }

// HardenProcess does nothing off OpenBSD.
func HardenProcess() {}

// Swept is one leftover that Sweep removed.
type Swept struct {
	Dir     string
	Mounted bool
}

// Sweep reports ErrUnsupported off OpenBSD.
func Sweep(base string) ([]Swept, error) { return nil, ErrUnsupported }

// SweepService reports ErrUnsupported off OpenBSD.
func SweepService(base, service string) ([]Swept, error) { return nil, ErrUnsupported }
