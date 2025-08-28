package cmd

import (
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// Internal
	"github.com/Method-Security/methodaws/internal/cloudfront"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"
)

// InitCloudFrontCommand initializes the `methodaws cloudfront` subcommand that deals with enumerating CloudFront distributions and their
// related resources.
func (a *MethodAws) InitCloudFrontCommand() {
	cloudFrontCmd := &cobra.Command{
		Use:   "cloudfront",
		Short: "Audit and command CloudFront distributions",
		Long:  `Audit and command CloudFront distributions`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate CloudFront distributions",
		Long:  `Enumerate CloudFront distributions`,
		Run: func(cmd *cobra.Command, args []string) {
			// Account ID
			accountID, err := utils.GetAccountID(cmd.Context(), *a.AwsConfig)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Config
			config := getCloudFrontEnumerateConfig(a.RootFlags.Regions, accountID)

			// Report
			report := cloudfront.EnumerateCloudFront(cmd.Context(), *a.AwsConfig, config)
			a.OutputSignal.Content = report
		},
	}

	cloudFrontCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(cloudFrontCmd)
}

func getCloudFrontEnumerateConfig(regions []string, accountID string) cloudfrontfern.CloudFrontEnumerateConfig {
	return cloudfrontfern.CloudFrontEnumerateConfig{
		Regions:   regions,
		AccountId: accountID,
	}
}
