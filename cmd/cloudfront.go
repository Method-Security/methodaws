package cmd

import (
	"github.com/Method-Security/methodaws/internal/cloudfront"
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
			report, err := cloudfront.EnumerateCloudFront(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	cloudFrontCmd.AddCommand(enumerateCmd)
	a.RootCmd.AddCommand(cloudFrontCmd)
}
