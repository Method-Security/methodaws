package cmd

import (
	// Internal
	"github.com/Method-Security/methodaws/internal/s3"
	"github.com/Method-Security/methodaws/utils"
	"github.com/spf13/cobra"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
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
			cfg := a.getS3EnumerateConfig(a.AwsConfig.Region, a.RootFlags.Regions)

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

	// Add Command to S3 Command
	s3Cmd.AddCommand(listCmd)

	// External Command
	externalEnumerateCmd := &cobra.Command{
		Use:   "external",
		Short: "Enumerate a single public facing S3 bucket from an external prespective.",
		Long:  `Enumerate a single public facing S3 bucket from an external prespective.`,
		Run: func(cmd *cobra.Command, args []string) {
			bucketURL, err := cmd.Flags().GetString("url")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			regions := a.RootFlags.Regions
			if len(regions) == 0 || regions[0] == "all" {
				regions = utils.GetGeneralRegions()
			}

			config := getExternalS3BucketConfig(regions, bucketURL)
			report := s3.ExternalEnumerateS3(cmd.Context(), config)
			a.OutputSignal.Content = report
		},
	}

	// Flags
	externalEnumerateCmd.Flags().String("url", "", "URL of the S3 bucket")

	_ = externalEnumerateCmd.MarkFlagRequired("url")

	// Add Command to S3 Command
	s3Cmd.AddCommand(externalEnumerateCmd)

	// Add S3 Command to Root Command
	a.RootCmd.AddCommand(s3Cmd)
}

// getS3EnumerateConfig returns a s3fern.S3EnumerateConfig with the given account ID and regions
func (a *MethodAws) getS3EnumerateConfig(accountID string, regions []string) s3fern.S3EnumerateConfig {
	return s3fern.S3EnumerateConfig{
		Regions: regions,
	}
}

// getExternalS3BucketConfig returns a s3fern.ExternalS3BucketConfig with the given regions and bucket URL
func getExternalS3BucketConfig(regions []string, bucketURL string) s3fern.S3ExternalConfig {
	return s3fern.S3ExternalConfig{
		BucketUrl: bucketURL,
		Regions:   regions,
	}
}

// getS3ListConfig returns a s3fern.ListS3BucketConfig with the given regions, and bucket name
func (a *MethodAws) getS3ListConfig(regions []string, bucketName string) s3fern.ListS3BucketConfig {
	return s3fern.ListS3BucketConfig{
		BucketName: bucketName,
		Regions:    regions,
	}
}
