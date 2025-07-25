package elasticbeanstalk

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// CreateEnvironment creates a new ElasticBeanstalk environment
func CreateEnvironment(ctx context.Context, awsConfig aws.Config, input *methodaws.ElasticBeanstalkCreateEnvironmentInput) *methodaws.ElasticBeanstalkCreateEnvironmentReport {
	log := svc1log.FromContext(ctx)
	
	log.Info("Starting ElasticBeanstalk environment creation",
		svc1log.SafeParam("environmentName", input.EnvironmentName),
		svc1log.SafeParam("applicationName", input.ApplicationName),
		svc1log.SafeParam("cnamePrefix", input.CnamePrefix),
		svc1log.SafeParam("region", input.Region))
	
	// Update the region in the config
	awsConfig.Region = input.Region

	client := elasticbeanstalk.NewFromConfig(awsConfig)

	createInput := &elasticbeanstalk.CreateEnvironmentInput{
		ApplicationName:   aws.String(input.ApplicationName),
		EnvironmentName:   aws.String(input.EnvironmentName),
		SolutionStackName: aws.String(input.SolutionStackName),
		CNAMEPrefix:       aws.String(input.CnamePrefix),
	}

	// Add the IAM instance profile option setting
	if input.IamInstanceProfile != "" {
		createInput.OptionSettings = []types.ConfigurationOptionSetting{
			{
				Namespace:  aws.String("aws:autoscaling:launchconfiguration"),
				OptionName: aws.String("IamInstanceProfile"),
				Value:      aws.String(input.IamInstanceProfile),
			},
		}
	}

	// Create config struct for reporting
	config := &methodaws.ElasticBeanstalkCreateEnvironmentConfig{
		ApplicationName:    &input.ApplicationName,
		EnvironmentName:    &input.EnvironmentName,
		SolutionStackName:  &input.SolutionStackName,
		IamInstanceProfile: &input.IamInstanceProfile,
		CnamePrefix:        input.CnamePrefix,
		Region:             input.Region,
	}

	result, err := client.CreateEnvironment(ctx, createInput)
	if err != nil {
		log.Error("Failed to create ElasticBeanstalk environment",
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("environmentName", input.EnvironmentName),
			svc1log.SafeParam("region", input.Region))
		errorMsg := err.Error()
		return &methodaws.ElasticBeanstalkCreateEnvironmentReport{
			Result: &methodaws.ElasticBeanstalkCreateEnvironmentResult{},
			Errors: []string{errorMsg},
			Config: config,
		}
	}

	log.Info("Successfully created ElasticBeanstalk environment",
		svc1log.SafeParam("environmentId", aws.ToString(result.EnvironmentId)),
		svc1log.SafeParam("environmentName", aws.ToString(result.EnvironmentName)),
		svc1log.SafeParam("cname", aws.ToString(result.CNAME)))

	// Convert AWS SDK result to Fern struct
	environment := &methodaws.ElasticBeanstalkEnvironment{
		EnvironmentId:   result.EnvironmentId,
		EnvironmentName: result.EnvironmentName,
		ApplicationName: result.ApplicationName,
		Cname:           result.CNAME,
		Region:          input.Region,
	}

	// Convert enum values using Fern helper functions
	if result.Status != "" {
		if status, err := methodaws.NewElasticBeanstalkEnvironmentStatusFromString(string(result.Status)); err == nil {
			environment.Status = &status
		}
	}

	if result.Health != "" {
		if health, err := methodaws.NewElasticBeanstalkEnvironmentHealthFromString(string(result.Health)); err == nil {
			environment.Health = &health
		}
	}

	return &methodaws.ElasticBeanstalkCreateEnvironmentReport{
		Result: &methodaws.ElasticBeanstalkCreateEnvironmentResult{
			Environment: environment,
		},
		Config: config,
	}
}

// CheckDNSAvailability checks if a CNAME prefix is available for use
func CheckDNSAvailability(ctx context.Context, awsConfig aws.Config, input *methodaws.ElasticBeanstalkDnsAvailabilityInput) *methodaws.ElasticBeanstalkDnsAvailabilityResult {
	log := svc1log.FromContext(ctx)
	
	log.Info("Checking ElasticBeanstalk DNS availability",
		svc1log.SafeParam("cnamePrefix", input.CnamePrefix),
		svc1log.SafeParam("region", input.Region))
	
	// Update the region in the config
	awsConfig.Region = input.Region
	
	client := elasticbeanstalk.NewFromConfig(awsConfig)

	checkInput := &elasticbeanstalk.CheckDNSAvailabilityInput{
		CNAMEPrefix: aws.String(input.CnamePrefix),
	}

	result, err := client.CheckDNSAvailability(ctx, checkInput)
	if err != nil {
		log.Error("Failed to check DNS availability",
			svc1log.SafeParam("error", err.Error()),
			svc1log.SafeParam("cnamePrefix", input.CnamePrefix),
			svc1log.SafeParam("region", input.Region))
		errorMsg := err.Error()
		return &methodaws.ElasticBeanstalkDnsAvailabilityResult{
			Available: false,
			Region:    input.Region,
			Error:     &errorMsg,
		}
	}

	available := result.Available != nil && *result.Available
	log.Info("DNS availability check completed",
		svc1log.SafeParam("cnamePrefix", input.CnamePrefix),
		svc1log.SafeParam("available", available),
		svc1log.SafeParam("fullyQualifiedCname", aws.ToString(result.FullyQualifiedCNAME)))

	return &methodaws.ElasticBeanstalkDnsAvailabilityResult{
		Available:            available,
		FullyQualifiedCname:  result.FullyQualifiedCNAME,
		Region:               input.Region,
	}
}
