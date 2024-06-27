package cmd

import (
	"github.com/Method-Security/methodaws/internal/s3"
	"github.com/spf13/cobra"
)

// InitS3Command initializes the `methodaws s3` subcommand that deals with enumerating S3 buckets and their related resources.
func (a *MethodAws) InitS3Command() {
	a.S3Cmd = &cobra.Command{
		Use:   "s3",
		Short: "Audit and manage S3 services",
		Long:  `Audit and manage S3 services`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all S3 buckets",
		Long:  `Enumerate all S3 buckets in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report, err := s3.EnumerateS3(cmd.Context(), *a.AwsConfig)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	lsCmd := &cobra.Command{
		Use:   "ls",
		Short: "List all objects in a single S3 bucket",
		Long:  `List all objects in a single S3 bucket.`,
		Run: func(cmd *cobra.Command, args []string) {
			bucketName, err := cmd.Flags().GetString("name")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}

			report, err := s3.LsS3Bucket(cmd.Context(), *a.AwsConfig, bucketName)
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = report
		},
	}

	lsCmd.Flags().String("name", "", "Name of the S3 bucket")

	a.S3Cmd.AddCommand(enumerateCmd)
	a.S3Cmd.AddCommand(lsCmd)
	a.RootCmd.AddCommand(a.S3Cmd)
}
