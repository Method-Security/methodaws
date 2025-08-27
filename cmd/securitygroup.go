package cmd

import (
	// Generated
	fernsecuritygroup "github.com/Method-Security/methodaws/generated/go/securitygroup"
	"github.com/Method-Security/methodaws/utils"

	// Internal
	"github.com/Method-Security/methodaws/internal/securitygroup"
	// External
	"github.com/spf13/cobra"
)

// InitSecurityGroupCommand initializes the `methodaws securitygroup` subcommand that deals with enumerating security
// groups and their related resources.
func (a *MethodAws) InitSecurityGroupCommand() {
	// Root Security Group Command
	// Subcommands
	// - enumerate
	securityGroupCmd := &cobra.Command{
		Use:     "security-group",
		Short:   "Audit and command security groups",
		Long:    `Audit and command security groups`,
		Aliases: []string{"sg"},
	}

	// Enumerate Command
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate security groups",
		Long:  `Enumerate security groups`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

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

			// Get Config
			config := getSecurityGroupEnumerateConfig(accountID, vpcID, a.RootFlags.Regions)

			// Get Report
			report := securitygroup.EnumerateSecurityGroups(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	enumerateCmd.Flags().String("vpc", "", "VPC ID to filter security groups by")

	securityGroupCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(securityGroupCmd)
}

func getSecurityGroupEnumerateConfig(accountID string, vpcID *string, regions []string) fernsecuritygroup.Ec2SecurityGroupsEnumerateConfig {
	return fernsecuritygroup.Ec2SecurityGroupsEnumerateConfig{
		AccountId: accountID,
		VpcId:     vpcID,
		Regions:   regions,
	}
}
