package cmd

import (
	// Internal
	"github.com/Method-Security/methodaws/internal/s3"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	external "github.com/Method-Security/methodaws/internal/s3/external"
)

// InitS3Command initializes the `methodaws s3` subcommand that deals with enumerating S3 buckets and their related resources.

func (a *MethodAws) InitS3Command() {

	// S3 Command
	// Subcommands:
	// - enumerate: Enumerate all S3 buckets in your AWS account.
	// - list: List all objects in a single S3 bucket.
	// - external: Enumerate a single public facing S3 bucket from an external prespective.
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "Audit and manage S3 services.",
		Long:  `Audit and manage S3 services.`,
	}

	// Enumerate Command
	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all S3 buckets",
		Long:  `Enumerate all S3 buckets in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Get Config
			cfg := a.getS3EnumerateConfig(a.RootFlags.Regions)

			// Get Report
			report, err := s3.EnumerateS3(cmd.Context(), *a.AwsConfig, cfg)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}
	s3Cmd.AddCommand(enumerateCmd)

	// List Command
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List all objects in a single S3 bucket",
		Long:  `List all objects in a single S3 bucket.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Config  Flags
			bucketName, err := cmd.Flags().GetString("name")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Get Config
			config := a.getS3ListConfig(a.RootFlags.Regions, bucketName)

			// Return report
			report, err := s3.ListS3Bucket(cmd.Context(), *a.AwsConfig, config)
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			a.OutputSignal.Content = report
		},
	}

	// Flags
	listCmd.Flags().String("name", "", "Name of the S3 bucket")

	_ = listCmd.MarkFlagRequired("name")

	// Add Command to S3 Command
	s3Cmd.AddCommand(listCmd)

	// External Command
	externalCmd := &cobra.Command{
		Use:   "external",
		Short: "Enumerate a single public facing S3 bucket from an external prespective.",
		Long:  `Enumerate a single public facing S3 bucket from an external prespective.`,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Override parent's PersistentPreRunE to use authed=false since external command uses anonymous credentials
			outputFormat, _ := cmd.Root().PersistentFlags().GetString("output")
			outputFile, _ := cmd.Root().PersistentFlags().GetString("output-file")
			return a.setupCommonConfig(cmd, outputFormat, outputFile, false)
		},
		Run: func(cmd *cobra.Command, args []string) {
			bucketURL, err := cmd.Flags().GetString("url")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}

			// Check if specific region was provided via --region flag
			// Override to not use the default region from the root command (us-east-1)
			regionFlag, err := cmd.Flags().GetString("region")
			if err != nil {
				a.OutputSignal.AddError(err)
				return
			}
			var regions []string
			if regionFlag != "" {
				// Use specific region if provided
				regions = []string{regionFlag}
			} else {
				// Default to all regions for external command (override root default of us-east-1)
				regions = utils.GetGeneralRegions()
			}

			config := getExternalS3BucketConfig(regions, bucketURL)
			report := external.EnumerateS3(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Flags
	externalCmd.Flags().String("url", "", "URL of the S3 bucket")
	externalCmd.Flags().String("region", "", "Region of the S3 bucket")

	_ = externalCmd.MarkFlagRequired("url")

	// Add Command to S3 Command
	s3Cmd.AddCommand(externalCmd)

	// Add S3 Command to Root Command
	a.RootCmd.AddCommand(s3Cmd)
}

// getS3EnumerateConfig returns a s3fern.S3EnumerateConfig with the given regions
func (a *MethodAws) getS3EnumerateConfig(regions []string) s3fern.S3EnumerateConfig {
	return s3fern.S3EnumerateConfig{
		Regions: regions,
	}
}

// getExternalS3BucketConfig returns a s3fern.ExternalS3BucketConfig with the given regions and bucket URL
func getExternalS3BucketConfig(regions []string, bucketURL string) s3fern.S3ExternalConfig {
	return s3fern.S3ExternalConfig{
		Url:     bucketURL,
		Regions: regions,
	}
}

// getS3ListConfig returns a s3fern.ListS3BucketConfig with the given regions, and bucket name
func (a *MethodAws) getS3ListConfig(regions []string, bucketName string) s3fern.ListS3BucketConfig {
	return s3fern.ListS3BucketConfig{
		BucketName: bucketName,
		Regions:    regions,
	}
}
