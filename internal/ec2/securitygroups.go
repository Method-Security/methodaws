package ec2

import (
	"context"
	"fmt"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnumerateSecurityGroups lists all of the security groups available to the caller across multiple regions
// alongside any non-fatal errors that occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, vpcID *string, regions []string) (SecurityGroupReport, error) {
	var allSecurityGroups []types.SecurityGroup
	var allErrors []string
	var accountID string

	if len(regions) > 0 {
		id, err := sts.GetAccountID(ctx, cfg)
		if err != nil {
			allErrors = append(allErrors, fmt.Sprintf("Error getting account ID: %v", err))
		} else {
			accountID = *id
		}
	}

	for _, region := range regions {
		securityGroups, errors := EnumerateSecurityGroupForRegion(ctx, cfg, vpcID, region)
		allSecurityGroups = append(allSecurityGroups, securityGroups...)
		allErrors = append(allErrors, errors...)
	}

	return SecurityGroupReport{
		AccountID:      accountID,
		SecurityGroups: allSecurityGroups,
		Errors:         allErrors,
	}, nil
}

// EnumerateSecurityGroupForRegion lists all of the security groups available to the caller for a specific region.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func EnumerateSecurityGroupForRegion(ctx context.Context, cfg aws.Config, vpcID *string, region string) ([]types.SecurityGroup, []string) {
	cfg.Region = region
	svc := ec2.NewFromConfig(cfg)
	var securityGroups []types.SecurityGroup
	var errors []string
	var filters []types.Filter

	if vpcID != nil {
		filters = append(filters, types.Filter{
			Name:   aws.String("vpc-id"),
			Values: []string{*vpcID},
		})
	}

	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{Filters: filters})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}

	return securityGroups, errors
}
