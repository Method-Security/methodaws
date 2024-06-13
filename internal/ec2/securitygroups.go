package ec2

import (
	"context"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, vpcID *string) (SecurityGroupReport, error) {
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
