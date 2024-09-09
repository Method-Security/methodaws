package cmd

import (
	"github.com/Method-Security/methodaws/internal/ec2"
	"github.com/spf13/cobra"
)

// InitSecurityGroupCommand initializes the `methodaws securitygroup` subcommand that deals with enumerating security
// groups and their related resources.
func (a *MethodAws) InitSecurityGroupCommand() {
	securityGroupCmd := &cobra.Command{
		Use:     "securitygroup",
		Short:   "Audit and command security groups",
		Long:    `Audit and command security groups`,
		Aliases: []string{"sg"},
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate security groups",
		Long:  `Enumerate security groups`,
		Run: func(cmd *cobra.Command, args []string) {
			var vpcID *string
			vpcIDFlag, err := cmd.Flags().GetString("vpc")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			if vpcIDFlag != "" {
				vpcID = &vpcIDFlag
			} else {
				vpcID = nil
			}

			report, err := ec2.EnumerateSecurityGroupsForRegion(cmd.Context(), *a.AwsConfig, vpcID, a.RootFlags.Regions[0])
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	enumerateCmd.Flags().String("vpc", "", "VPC ID to filter security groups by")

	securityGroupCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(securityGroupCmd)
}
