//go:build linux

package main

import "github.com/spf13/cobra"

func init() {
	runFlow = func(cmd *cobra.Command, p *runPlan) error {
		return runS6(s6Flags{
			service: p.service, user: p.user, baseDir: p.base, source: p.source,
			secret: p.secret, machineIDFile: p.machineIDFile, unshare: true,
			allowNull: p.allowNull, keepCap: p.keepCap,
		}, append([]string{p.program}, p.args...))
	}
}
