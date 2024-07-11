package ec2

import (
	"context"
	"fmt"
	"strings"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// EnumerateEc2 enumerates all of the EC2 instances that the caller has access to. It returns a ResourceReport struct
// that contains the EC2 instances and any non-fatal errors that occurred during the execution of the subcommand.
func EnumerateEc2(ctx context.Context, cfg aws.Config) (*ResourceReport, error) {
	// Create EC2 and IAM service clients
	svc := ec2.NewFromConfig(cfg)
	iamSvc := iam.NewFromConfig(cfg)
	resources := Instances{}
	errors := []string{}

	// Get the account ID
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &ResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	// Initialize an empty slice to store all instances
	var ec2Instances []InstanceWithIAMRole

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
			for _, inst := range r.Instances {
				instanceWithRole := InstanceWithIAMRole{
					Instance: inst,
				}

				if inst.IamInstanceProfile != nil {
					roles, err := getIAMRoles(ctx, iamSvc, *inst.IamInstanceProfile.Arn)
					if err != nil {
						errors = append(errors, err.Error())
					}
					instanceWithRole.IAMRoles = roles
				}

				ec2Instances = append(ec2Instances, instanceWithRole)
			}
		}
	}

	if ec2Instances != nil {
		resources.EC2Instances = ec2Instances
	}

	report := ResourceReport{
		AccountID: aws.ToString(accountID),
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}

// extractInstanceProfileName extracts the instance profile name from the ARN
func extractInstanceProfileName(profileArn string) string {
	parts := strings.Split(profileArn, "/")
	return parts[len(parts)-1]
}

// extractAccountIDFromARN extracts the account ID from the ARN
func extractAccountIDFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[4]
}

// constructIAMRoleARN constructs the IAM role ARN given the role name and account ID.
func constructIAMRoleARN(roleName, accountID string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
}

// getIAMRoles retrieves the IAM roles associated with the the instance profile name
func getIAMRoles(ctx context.Context, iamSvc *iam.Client, instanceProfileArn string) ([]string, error) {
	instanceProfileName := extractInstanceProfileName(instanceProfileArn)
	accountID := extractAccountIDFromARN(instanceProfileArn)
	roles := []string{}

	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: &instanceProfileName,
	}

	result, err := iamSvc.GetInstanceProfile(ctx, input)
	if err != nil {
		return roles, err
	}

	for _, role := range result.InstanceProfile.Roles {
		roles = append(roles, constructIAMRoleARN(*role.RoleName, accountID))
	}

	return roles, fmt.Errorf("no roles found in instance profile - %s", instanceProfileName)
}
