package cmd

import (
	"os"

	"github.com/Method-Security/methodaws/internal/common"
	"github.com/Method-Security/methodaws/internal/s3"
	"github.com/palantir/witchcraft-go-logging/wlog"

	// Import wlog-zap for its side effects, initializing the zap logger
	_ "github.com/palantir/witchcraft-go-logging/wlog-zap"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitS3Command initializes the `methodaws s3` subcommand that deals with enumerating S3 buckets and their related resources.
func (a *MethodAws) InitS3Command() {
	s3Cmd := &cobra.Command{
		Use:   "s3",
		Short: "Audit and manage S3 services",
		Long:  `Audit and manage S3 services`,
	}

	enumerateCmd := &cobra.Command{
		Use:   "enumerate",
		Short: "Enumerate all S3 buckets",
		Long:  `Enumerate all S3 buckets in your AWS account.`,
		Run: func(cmd *cobra.Command, args []string) {
			report := s3.EnumerateS3(cmd.Context(), *a.AwsConfig, a.RootFlags.Regions)
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

	externalEnumerateCmd := &cobra.Command{
		Use:   "externalenumerate",
		Short: "Enumerate a single public facing S3 bucket.",
		Long:  `Enumerate a single public facing S3 bucket with no credentials.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			logger := svc1log.New(os.Stdout, wlog.InfoLevel)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), logger))
			log := svc1log.FromContext(cmd.Context())

			// For s3 externalenumerate, just get the regions without checking
			a.RootFlags.Regions = common.GetRegionsToCheck(a.RootFlags.Regions, log)
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			bucketName, err := cmd.Flags().GetString("name")
			if err != nil {
				errorMessage := err.Error()
				a.OutputSignal.ErrorMessage = &errorMessage
				a.OutputSignal.Status = 1
				return
			}
			report := s3.ExternalEnumerateS3(cmd.Context(), bucketName, a.RootFlags.Regions)
			a.OutputSignal.Content = report
		},
	}

	externalEnumerateCmd.Flags().String("name", "", "Name of the S3 bucket")

	s3Cmd.AddCommand(enumerateCmd)
	s3Cmd.AddCommand(lsCmd)
	s3Cmd.AddCommand(externalEnumerateCmd)
	a.RootCmd.AddCommand(s3Cmd)
}
