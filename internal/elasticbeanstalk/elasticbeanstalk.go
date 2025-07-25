package elasticbeanstalk

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
)

// CreateEnvironment creates a new ElasticBeanstalk environment
func CreateEnvironment(ctx context.Context, awsConfig aws.Config, input *methodaws.ElasticBeanstalkCreateEnvironmentInput) *methodaws.ElasticBeanstalkCreateEnvironmentResult {
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

	result, err := client.CreateEnvironment(ctx, createInput)
	if err != nil {
		errorMsg := err.Error()
		return &methodaws.ElasticBeanstalkCreateEnvironmentResult{
			Error: &errorMsg,
		}
	}

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

	return &methodaws.ElasticBeanstalkCreateEnvironmentResult{
		Environment: environment,
	}
}