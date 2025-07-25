package cmd

import (
	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"
)

// InitElasticBeanstalkCommand initializes the `methodaws elasticbeanstalk` subcommand
func (a *MethodAws) InitElasticBeanstalkCommand() {
	ebCmd := &cobra.Command{
		Use:   "elasticbeanstalk",
		Short: "Manage ElasticBeanstalk applications and environments",
		Long:  `Manage ElasticBeanstalk applications and environments`,
	}

	createEnvCmd := &cobra.Command{
		Use:   "create-environment",
		Short: "Create a new ElasticBeanstalk environment",
		Long:  `Create a new ElasticBeanstalk environment with specified configuration`,
		Run: func(cmd *cobra.Command, args []string) {
			applicationName, _ := cmd.Flags().GetString("application-name")
			solutionStack, _ := cmd.Flags().GetString("solution-stack")
			iamInstanceProfile, _ := cmd.Flags().GetString("iam-instance-profile")
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")

			// Generate environment name from cname prefix
			environmentName := cnamePrefix + "-env"

			// Use the first region from global flags (already validated in PersistentPreRunE)
			if len(a.RootFlags.Regions) == 0 {
				a.OutputSignal.ErrorMessage = aws.String("No valid AWS regions found or specified")
				a.OutputSignal.Status = 1
				return
			}
			targetRegion := a.RootFlags.Regions[0]

			// First check if the CNAME prefix is available
			dnsInput := &methodaws.ElasticBeanstalkDnsAvailabilityInput{
				CnamePrefix: cnamePrefix,
				Region:      targetRegion,
			}

			dnsResult := elasticbeanstalk.CheckDNSAvailability(cmd.Context(), *a.AwsConfig, dnsInput)
			if dnsResult.Error != nil {
				a.OutputSignal.ErrorMessage = dnsResult.Error
				a.OutputSignal.Status = 1
				return
			}

			if !dnsResult.Available {
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
				Region:             targetRegion,
			}

			result := elasticbeanstalk.CreateEnvironment(cmd.Context(), *a.AwsConfig, input)
			if result.Error != nil {
				a.OutputSignal.ErrorMessage = result.Error
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

	// Mark required flags
	_ = createEnvCmd.MarkFlagRequired("cname-prefix")

	checkDnsCmd := &cobra.Command{
		Use:   "check-dns-availability",
		Short: "Check if a CNAME prefix is available for ElasticBeanstalk",
		Long:  `Check if a CNAME prefix is available for use with ElasticBeanstalk environments`,
		Run: func(cmd *cobra.Command, args []string) {
			cnamePrefix, _ := cmd.Flags().GetString("cname-prefix")

			// Use the first region from global flags (already validated in PersistentPreRunE)
			if len(a.RootFlags.Regions) == 0 {
				a.OutputSignal.ErrorMessage = aws.String("No valid AWS regions found or specified")
				a.OutputSignal.Status = 1
				return
			}
			targetRegion := a.RootFlags.Regions[0]

			input := &methodaws.ElasticBeanstalkDnsAvailabilityInput{
				CnamePrefix: cnamePrefix,
				Region:      targetRegion,
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
	checkDnsCmd.Flags().String("cname-prefix", "", "CNAME prefix to check availability for (required)")
	_ = checkDnsCmd.MarkFlagRequired("cname-prefix")

	ebCmd.AddCommand(createEnvCmd)
	ebCmd.AddCommand(checkDnsCmd)
	a.RootCmd.AddCommand(ebCmd)
}
