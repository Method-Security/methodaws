package cmd

import (
	"github.com/Method-Security/methodaws/internal/vpc"
	"github.com/spf13/cobra"
)

func (a *MethodAws) InitVPCCommand() {
	a.VpcCmd = &cobra.Command{
		Use:   "vpc",
		Short: "Audit and manage VPC services",
		Long:  `Audit and manage VPC services`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all VPCs",
		Long:  `Enumerate all VPCs in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := vpc.EnumerateVPC(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	a.VpcCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(a.VpcCmd)
}
