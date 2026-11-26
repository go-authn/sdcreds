package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/go-authn/sdcreds/delivery"
)

// sweepCmd removes what a crashed run left behind: the mount, the directory and
// the lock file. `run` sweeps its own service at start; this is for a machine
// where nobody wants to start the service to clean it.
func sweepCmd() *cobra.Command {
	var base, service string
	cmd := &cobra.Command{
		Use:   "sweep [--base DIR] [--service S]",
		Short: "remove the leftovers of crashed runs (OpenBSD)",
		Long: "Unmounts and removes the credential directories under BASE that no running sdcreds\n" +
			"holds, and their stale lock files. A service whose lock is held by a running\n" +
			"instance is left alone. With --service only that service is swept.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if base == "" {
				base = defaultBase()
			}
			var sw []delivery.Swept
			var err error
			if service != "" {
				sw, err = delivery.SweepService(base, service)
			} else {
				sw, err = delivery.Sweep(base)
			}
			for _, s := range sw {
				fmt.Fprintf(cmd.OutOrStdout(), "swept %s (mounted: %v)\n", s.Dir, s.Mounted)
			}
			if errors.Is(err, delivery.ErrUnsupported) {
				err = &refusal{err}
			}
			if err == nil && len(sw) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "nothing to sweep")
			}
			var r *refusal
			if errors.As(err, &r) {
				fmt.Fprintf(cmd.ErrOrStderr(), "sdcreds sweep: %v\n", r)
				osExit(exitRefused)
				return nil
			}
			return err
		},
	}
	fl := cmd.Flags()
	fl.StringVar(&base, "base", "", "directory holding one credential directory per service (default "+delivery.DefaultBase+")")
	fl.StringVar(&service, "service", "", "sweep only this service")
	return cmd
}
