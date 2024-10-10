package cmd

import (
	"github.com/Method-Security/methodaws/internal/waf"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitWAFCommand() {
	wafCmd := &cobra.Command{
		Use:   "waf",
		Short: "Audit and manage WAFs",
		Long:  `Audit and manage WAFs`,
	}

	enumerateWAF := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate WAFs",
		Long:  `Enumerate WAFs in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {

			report, err := waf.EnumerateWAF(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	wafCmd.AddCommand(enumerateWAF)
	a.RootCmd.AddCommand(wafCmd)
}
