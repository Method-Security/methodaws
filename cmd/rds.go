package cmd

import (
	"github.com/Method-Security/methodaws/internal/rds"
	"github.com/spf13/cobra"
)

// InitRdsCommand initializes the `methodaws rds` subcommand that deals with enumerating RDS instances in the AWS account.
func (a *MethodAws) InitRdsCommand() {
	rdsCmd := &cobra.Command{
		Use:   "rds",
		Short: "Audit and manage RDS instances",
		Long:  `Audit and manage RDS instances`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate RDS instances",
		Long:  `Enumerate RDS instances in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := rds.EnumerateRds(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	rdsCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(rdsCmd)
}
