// Package cmd implements the CobraCLI commands for the methodaws CLI. Subcommands for the CLI should all live within
// this package. Logic should be delegated to internal packages and functions to keep the CLI commands clean and
// focused on CLI I/O.
package cmd

import (
	"errors"
	"strings"
	"time"

	"github.com/Method-Security/methodaws/internal/common"
	"github.com/Method-Security/methodaws/internal/config"
	"github.com/Method-Security/pkg/signal"
	"github.com/Method-Security/pkg/writer"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/palantir/pkg/datetime"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// MethodAws is the main struct that holds the root command and all subcommands that are used throughout execution
// of the CLI. It is also responsible for holding the AWS configuration, Output configuration, and Output signal
// for use by subcommands. The output signal is used to write the output of the command to the desired output format
// after the execution of the invoked commands Run function.
type MethodAws struct {
	Version      string
	RootFlags    config.RootFlags
	OutputConfig writer.OutputConfig
	OutputSignal signal.Signal
	AwsConfig    *aws.Config
	RootCmd      *cobra.Command
}

// NewMethodAws returns a new MethodAws struct with the provided version string. The MethodAws struct is used to
// initialize the root command and all subcommands that are used throughout execution of the CLI.
// We pass the version command in here from the main.go file, where we set the version string during the build process.
func NewMethodAws(version string) *MethodAws {
	methodAws := MethodAws{
		Version: version,
		RootFlags: config.RootFlags{
			Quiet:   false,
			Verbose: false,
			Regions: []string{},
		},
		OutputConfig: writer.NewOutputConfig(nil, writer.NewFormat(writer.SIGNAL)),
		OutputSignal: signal.NewSignal(nil, datetime.DateTime(time.Now()), nil, 0, nil),
		AwsConfig:    nil,
	}
	return &methodAws
}

// InitRootCommand initializes the root command for the methodaws CLI. This command is used to set the global flags
// that are used by all subcommands, such as the region, output format, and output file. It also initializes the
// version command that prints the version of the CLI.
// Critically, this sets the PersistentPreRunE and PersistentPostRunE functions that are inherited by all subcommands.
// The PersistentPreRunE function is used to validate the region flag and set the AWS configuration. The PersistentPostRunE
// function is used to write the output of the command to the desired output format after the execution of the invoked
// command's Run function.
func (a *MethodAws) InitRootCommand() {
	var outputFormat string
	var outputFile string
	a.RootCmd = &cobra.Command{
		Use:          "methodaws",
		Short:        "Audit AWS resources",
		Long:         "Audit AWS resources",
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			var err error

			format, err := validateOutputFormat(outputFormat)
			if err != nil {
				return err
			}
			var outputFilePointer *string
			if outputFile != "" {
				outputFilePointer = &outputFile
			} else {
				outputFilePointer = nil
			}
			a.OutputConfig = writer.NewOutputConfig(outputFilePointer, format)
			a.RootFlags.Regions = common.GetAWSRegions(a.RootFlags.Regions)
			cmd.SetContext(svc1log.WithLogger(cmd.Context(), config.InitializeLogging(cmd, &a.RootFlags)))
			awsconfig, err := awsconfig.LoadDefaultConfig(cmd.Context())
			if err != nil {
				return err
			}
			a.AwsConfig = &awsconfig

			return nil
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			completedAt := datetime.DateTime(time.Now())
			a.OutputSignal.CompletedAt = &completedAt
			return writer.Write(
				a.OutputSignal.Content,
				a.OutputConfig,
				a.OutputSignal.StartedAt,
				a.OutputSignal.CompletedAt,
				a.OutputSignal.Status,
				a.OutputSignal.ErrorMessage,
			)
		},
	}

	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Quiet, "quiet", "q", false, "Suppress output")
	a.RootCmd.PersistentFlags().BoolVarP(&a.RootFlags.Verbose, "verbose", "v", false, "Verbose output")
	a.RootCmd.PersistentFlags().StringArrayVarP(&a.RootFlags.Regions, "region", "r", []string{}, "AWS Regions to search for resources. You can specify multiple regions by providing the flag multiple times. If blank, will search all regions.")
	a.RootCmd.PersistentFlags().StringVarP(&outputFile, "output-file", "f", "", "Path to output file. If blank, will output to STDOUT")
	a.RootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "signal", "Output format (signal, json, yaml). Default value is signal")

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version number of methodaws",
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(a.Version)
		},
		PersistentPostRunE: func(cmd *cobra.Command, _ []string) error {
			return nil
		},
	}

	a.RootCmd.AddCommand(versionCmd)
}

// A utility function to validate that the provided output format is one of the supported formats: json, yaml, signal.
func validateOutputFormat(output string) (writer.Format, error) {
	var format writer.FormatValue
	switch strings.ToLower(output) {
	case "json":
		format = writer.JSON
	case "yaml":
		return writer.Format{}, errors.New("yaml output format is not supported for methodaws")
	case "signal":
		format = writer.SIGNAL
	default:
		return writer.Format{}, errors.New("invalid output format. Valid formats are: json, yaml, signal")
	}
	return writer.NewFormat(format), nil
}
