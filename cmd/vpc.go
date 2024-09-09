package cmd

import (
	"github.com/Method-Security/methodaws/internal/vpc"
	"github.com/spf13/cobra"
)

// InitVPCCommand initializes the `methodaws vpc` subcommand that deals with enumerating VPCs and related resources in
// the AWS account.
func (a *MethodAws) InitVPCCommand() {
	vpcCmd := &cobra.Command{
		Use:   "vpc",
		Short: "Audit and manage VPC services",
		Long:  `Audit and manage VPC services`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all VPCs",
		Long:  `Enumerate all VPCs in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := vpc.EnumerateVPC(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	vpcCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(vpcCmd)
}
