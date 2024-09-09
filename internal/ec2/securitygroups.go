package ec2

import (
	"context"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnumerateSecurityGroupsForRegion lists all of the security groups available to the caller alongside any non-fatal errors that
// occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func EnumerateSecurityGroupsForRegion(ctx context.Context, cfg aws.Config, vpcID *string, region string) (SecurityGroupReport, error) {
	cfg.Region = region

	svc := ec2.NewFromConfig(cfg)
	errors := []string{}
	var securityGroups []types.SecurityGroup
	var filters []types.Filter
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return SecurityGroupReport{
			SecurityGroups: securityGroups,
			Errors:         errors,
		}, err
	}

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
			errors = append(errors, err.Error())
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}

	return SecurityGroupReport{
		AccountID:      *accountID,
		SecurityGroups: securityGroups,
		Errors:         errors,
	}, nil
}
