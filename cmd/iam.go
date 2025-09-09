package cmd

import (
	iam "github.com/Method-Security/methodaws/generated/go/iam"
	iamInternal "github.com/Method-Security/methodaws/internal/iam/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitIamCommand initializes the `methodaws iam` subcommand that deals with enumerating IAM roles, attached policies,
// inline policies and assume role policies within the AWS account.
func (a *MethodAws) InitIamCommand() {
	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Audit and command IAM resources",
		Long:  `Audit and command IAM resources`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate IAM resources",
		Long:  `Enumerate IAM resources`,
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getIamEnumerateConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := iamInternal.EnumerateIam(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	iamCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(iamCmd)
}

// getIamEnumerateConfig returns an IamEnumerateConfig with the given regions and account ID
func getIamEnumerateConfig(regions []string, accountID string) iam.IamEnumerateConfig {
	return iam.IamEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
