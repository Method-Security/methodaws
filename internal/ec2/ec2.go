// Package ec2 contains all logic and data structures relevant to enumerating EC2 instances and their related,
// resources, including security groups and network interfaces. It is primarily utilized by the `methodaws ec2` an
// `methodaws securitygroup` subcommands.
package ec2

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnumerateEc2 enumerates all of the EC2 instances that the caller has access to. It returns a ResourceReport struct
// that contains the EC2 instances and any non-fatal errors that occurred during the execution of the subcommand.
func EnumerateEc2(ctx context.Context, cfg aws.Config) (*ResourceReport, error) {
	// Create an EC2 service client
	svc := ec2.NewFromConfig(cfg)
	resources := Instances{}
	errors := []string{}

	// Initialize an empty slice to store all instances
	var ec2Instances []types.Instance

	// Function to process pages of instances
	paginator := ec2.NewDescribeInstancesPaginator(svc, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		// Retrieve the next page
		result, err := paginator.NextPage(context.TODO())
		if err != nil {
			errors = append(errors, err.Error())
			break
		}

		// Loop through the reservations and instances
		for _, r := range result.Reservations {
			ec2Instances = append(ec2Instances, r.Instances...)
		}
	}

	if ec2Instances != nil {
		resources.EC2Instances = ec2Instances
	}

	report := ResourceReport{
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}
