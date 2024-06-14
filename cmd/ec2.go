package cmd

import (
	"github.com/Method-Security/methodaws/internal/ec2"
	"github.com/spf13/cobra"
)

// Initialize the `methodaws ec2` subcommand that deals with enumerating EC2 instances and their related resources.
func (a *MethodAws) InitEc2Command() {
	ec2Cmd := &cobra.Command{
		Use:   "ec2",
		Short: "Audit and command EC2 instances",
		Long:  `Audit and command EC2 instances`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate EC2 instances",
		Long:  `Enumerate EC2 instances`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := ec2.EnumerateEc2(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	ec2Cmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(ec2Cmd)
}
