//go:build !openbsd

package delivery

import (
	"context"
	"os"
)

type state struct{ lost chan struct{} }

func prepare(ctx context.Context, c Config) (*Delivery, error) { return nil, ErrUnsupported }

func (d *Delivery) release() error { return nil }

func (d *Delivery) guardGroup(pgid int) error { return ErrUnsupported }

// ServeMFS reports ErrUnsupported off OpenBSD.
func ServeMFS(argv []string, ctl *os.File) error { return ErrUnsupported }

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
