package vpc

import (
	"context"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EnumerateVPC lists the VPCs available to the caller and returns a Report struct. The Report contains all non-fatal errors
// that occurred during the execution of the `methodaws vpc enumerate` subcommand. EnumerateVPC will return an error
// if the account ID cannot be retrieved.
func EnumerateVPC(ctx context.Context, cfg aws.Config) (report Report, err error) {
	svc := ec2.NewFromConfig(cfg)
	paginator := ec2.NewDescribeVpcsPaginator(svc, &ec2.DescribeVpcsInput{})

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return Report{
			AccountID: "",
			VPCs:      []Instance{},
			Errors:    []string{err.Error()},
		}, err
	}

	vpcs := []Instance{}
	errors := []string{}

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, err.Error())
			break
		}

		for _, vpc := range result.Vpcs {
			vpcs = append(vpcs, Instance{VPC: vpc})
		}
	}

	return Report{
		AccountID: *accountID,
		VPCs:      vpcs,
		Errors:    errors,
	}, nil
}
