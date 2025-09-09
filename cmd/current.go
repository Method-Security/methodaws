package cmd

import (
	currentfern "github.com/Method-Security/methodaws/generated/go/current"
	current "github.com/Method-Security/methodaws/internal/current/enumerate"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitCurrentCommand initializes the `methodaws current` subcommand that deals with evaluating the current
// properties and capabilities of an AWS instance.
func (a *MethodAws) InitCurrentCommand() {
	currentCmd := &cobra.Command{
		Use:   "current",
		Short: "Describe the current AWS instance",
		Long:  "Describe the current AWS instance",
	}

	describeCmd := &cobra.Command{
		Use:   "describe",
		Short: "Describe the current AWS instance",
		Long:  "Describe the current AWS instance",
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getCurrentInstanceConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := current.EnumerateCurrentInstance(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	iamCmd := &cobra.Command{
		Use:   "iam",
		Short: "Describe the IAM role of the current AWS instance",
		Long:  "Describe the IAM role of the current AWS instance",
		Run: func(cmd *cobra.Command, args []string) {
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := getCurrentIamConfig(a.RootFlags.Regions, accountID)

			// Get Report
			report := current.EnumerateCurrentIam(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	currentCmd.AddCommand(describeCmd)
	currentCmd.AddCommand(iamCmd)
	a.RootCmd.AddCommand(currentCmd)
}

// getCurrentInstanceConfig returns a CurrentInstanceConfig with the given regions and account ID
func getCurrentInstanceConfig(regions []string, accountID string) currentfern.CurrentInstanceConfig {
	return currentfern.CurrentInstanceConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}

// getCurrentIamConfig returns a CurrentIamConfig with the given regions and account ID
func getCurrentIamConfig(regions []string, accountID string) currentfern.CurrentIamConfig {
	return currentfern.CurrentIamConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
