package vpc

import (
	"context"
	"fmt"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// EnumerateVPCForRegion lists the VPCs available to the caller for a particular regionand returns a Report struct. The Report
// contains all non-fatal errors that occurred during the execution of the `methodaws vpc enumerate` subcommand.
// EnumerateVPCForRegion will return an error if the account ID cannot be retrieved.
func EnumerateVPCForRegion(ctx context.Context, cfg aws.Config, region string) (report Report, err error) {
	cfg.Region = region

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
			vpcs = append(vpcs, Instance{VPC: vpc, Region: region})
		}
	}

	return Report{
		AccountID: *accountID,
		VPCs:      vpcs,
		Errors:    errors,
	}, nil
}

// EnumerateVPC lists the VPCs available to the caller and returns a Report struct for each specified region. The Report
// contains all non-fatal errors that occurred during the execution of the `methodaws vpc enumerate` subcommand.
// This method consolidates individual region reports into a single report.
func EnumerateVPC(ctx context.Context, cfg aws.Config, regions []string) (report Report, err error) {
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return Report{
			AccountID: "",
			VPCs:      []Instance{},
			Errors:    []string{err.Error()},
		}, err
	}

	report = Report{
		AccountID: *accountID,
		VPCs:      []Instance{},
		Errors:    []string{},
	}

	for _, region := range regions {
		r, err := EnumerateVPCForRegion(ctx, cfg, region)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Error in region %s: %s", region, err.Error()))
			continue
		}
		if r.VPCs != nil {
			report.VPCs = append(report.VPCs, r.VPCs...)
		}
	}

	return report, nil
}
