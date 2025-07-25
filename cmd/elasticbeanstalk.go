package cmd

import (
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
	"github.com/spf13/cobra"
)

// InitElasticBeanstalkCommand initializes the `methodaws elasticbeanstalk` subcommand
func (a *MethodAws) InitElasticBeanstalkCommand() {
	ebCmd := &cobra.Command{
		Use:   "elasticbeanstalk",
		Short: "Manage ElasticBeanstalk applications and environments",
		Long:  `Manage ElasticBeanstalk applications and environments`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Override root command's PersistentPreRunE to prevent region validation
			return nil
		},
	}

	createEnvCmd := &cobra.Command{
		Use:   "create-environment",
		Short: "Create a new ElasticBeanstalk environment",
		Long:  `Create a new ElasticBeanstalk environment with specified configuration`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			// Manually validate required flags
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")
			region, _ := cmd.Flags().GetString("region")

			if cnamePrefix == "" {
				return fmt.Errorf("required flag \"cname-prefix\" not set")
			}
			if region == "" {
				return fmt.Errorf("required flag \"region\" not set")
			}

			outputFormat, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}
			outputFile, err := cmd.Flags().GetString("output-file")
			if err != nil {
				return err
			}
			// Override the global regions with our local region flag
			a.RootFlags.Regions = []string{region}
			return a.setupCommonConfig(cmd, outputFormat, outputFile, true)
		},
		Run: func(cmd *cobra.Command, args []string) {
			applicationName, _ := cmd.Flags().GetString("application-name")
			solutionStack, _ := cmd.Flags().GetString("solution-stack")
			iamInstanceProfile, _ := cmd.Flags().GetString("iam-instance-profile")
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")
			region, _ := cmd.Flags().GetString("region")

			// Generate environment name from cname prefix
			environmentName := cnamePrefix + "-env"

			// First check if the CNAME prefix is available
			dnsInput := &methodaws.ElasticBeanstalkDnsAvailabilityInput{
				CnamePrefix: cnamePrefix,
				Region:      region,
			}

			dnsResult := elasticbeanstalk.CheckDNSAvailability(cmd.Context(), *a.AwsConfig, dnsInput)
			if dnsResult.Error != nil {
				a.OutputSignal.ErrorMessage = dnsResult.Error
				a.OutputSignal.Status = 1
				return
			}

			if !dnsResult.Available {
				log := svc1log.FromContext(cmd.Context())
				log.Warn("CNAME prefix is not available, aborting environment creation",
					svc1log.SafeParam("cnamePrefix", cnamePrefix),
					svc1log.SafeParam("fullyQualifiedCname", aws.ToString(dnsResult.FullyQualifiedCname)))
				errorMsg := "CNAME prefix '" + cnamePrefix + "' is not available. The fully qualified CNAME would be: " + aws.ToString(dnsResult.FullyQualifiedCname)
				a.OutputSignal.ErrorMessage = &errorMsg
				a.OutputSignal.Status = 1
				return
			}

			// CNAME is available, proceed with environment creation
			input := &methodaws.ElasticBeanstalkCreateEnvironmentInput{
				ApplicationName:    applicationName,
				EnvironmentName:    environmentName,
				SolutionStackName:  solutionStack,
				IamInstanceProfile: iamInstanceProfile,
				CnamePrefix:        cnamePrefix,
				Region:             region,
			}

			result := elasticbeanstalk.CreateEnvironment(cmd.Context(), *a.AwsConfig, input)
			if len(result.Errors) > 0 {
				errorMsg := result.Errors[0] // Use first error
				a.OutputSignal.ErrorMessage = &errorMsg
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = result
		},
	}

	// Add flags for the create-environment command
	createEnvCmd.Flags().String("application-name", "sample-app", "Name of the ElasticBeanstalk application")
	createEnvCmd.Flags().String("solution-stack", "64bit Amazon Linux 2023 v4.6.1 running Python 3.13", "Solution stack name")
	createEnvCmd.Flags().String("iam-instance-profile", "ec2-instance-role", "IAM instance profile for EC2 instances")
	createEnvCmd.Flags().String("cname-prefix", "", "CNAME prefix for the environment (required)")
	createEnvCmd.Flags().String("region", "", "AWS region for the environment (required)")

	// Required flags are manually validated in PreRunE

	checkDNSCmd := &cobra.Command{
		Use:   "check-dns-availability",
		Short: "Check if a CNAME prefix is available for ElasticBeanstalk",
		Long:  `Check if a CNAME prefix is available for use with ElasticBeanstalk environments`,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			// Manually validate required flags
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")
			region, _ := cmd.Flags().GetString("region")

			if cnamePrefix == "" {
				return fmt.Errorf("required flag \"cname-prefix\" not set")
			}
			if region == "" {
				return fmt.Errorf("required flag \"region\" not set")
			}

			outputFormat, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}
			outputFile, err := cmd.Flags().GetString("output-file")
			if err != nil {
				return err
			}
			// Override the global regions with our local region flag
			a.RootFlags.Regions = []string{region}
			return a.setupCommonConfig(cmd, outputFormat, outputFile, true)
		},
		Run: func(cmd *cobra.Command, args []string) {
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")
			region, _ := cmd.Flags().GetString("region")

			input := &methodaws.ElasticBeanstalkDnsAvailabilityInput{
				CnamePrefix: cnamePrefix,
				Region:      region,
			}

			result := elasticbeanstalk.CheckDNSAvailability(cmd.Context(), *a.AwsConfig, input)
			if result.Error != nil {
				a.OutputSignal.ErrorMessage = result.Error
				a.OutputSignal.Status = 1
			}
			a.OutputSignal.Content = result
		},
	}

	// Add flags for the check-dns-availability command
	checkDNSCmd.Flags().String("cname-prefix", "", "CNAME prefix to check availability for (required)")
	checkDNSCmd.Flags().String("region", "", "AWS region to check availability in (required)")
	// Required flags are manually validated in PreRunE

	ebCmd.AddCommand(createEnvCmd)
	ebCmd.AddCommand(checkDNSCmd)
	a.RootCmd.AddCommand(ebCmd)
}
