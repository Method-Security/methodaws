package cloudfront

import (
	"context"
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
)

func EnumerateCloudFrontForRegion(ctx context.Context, cfg aws.Config, region string) (*methodaws.CloudFrontReport, error) {
	cfg.Region = region

	svc := cloudfront.NewFromConfig(cfg)

	paginator := cloudfront.NewListDistributionsPaginator(svc, &cloudfront.ListDistributionsInput{})

	report := methodaws.CloudFrontReport{
		AccountId:     "",
		Distributions: []*methodaws.CloudFrontDistribution{},
		Errors:        []string{},
	}

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, dist := range output.DistributionList.Items {
			origins := []*methodaws.CloudFrontDistributionOrigin{}
			for _, origin := range dist.Origins.Items {
				origins = append(origins, &methodaws.CloudFrontDistributionOrigin{
					DomainName: origin.DomainName,
					Id:         *origin.Id,
				})
			}

			// check that the comment exists, avoid passing back an empty string
			var comment *string
			if dist.Comment != nil && len(*dist.Comment) > 0 {
				comment = dist.Comment
			}

			// check CDN enabled status
			var status methodaws.CloudFrontDistributionStatus = methodaws.CloudFrontDistributionStatusEnabled
			if !*dist.Enabled {
				status = methodaws.CloudFrontDistributionStatusDisabled
			}

			distribution := &methodaws.CloudFrontDistribution{
				Arn:        *dist.ARN,
				DomainName: *dist.DomainName,
				Comment:    comment,
				Origins:    origins,
				Status:     status,
			}
			report.Distributions = append(report.Distributions, distribution)
		}
	}

	return &report, nil
}

func EnumerateCloudFront(ctx context.Context, cfg aws.Config, regions []string) (*methodaws.CloudFrontReport, error) {
	// try to setup an account id
	accountId, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		// return a resource report with error information if we can't get id
		return &methodaws.CloudFrontReport{
			AccountId:     aws.ToString(accountId),
			Distributions: []*methodaws.CloudFrontDistribution{},
			Errors:        []string{err.Error()},
		}, err
	}

	// initialize a resource report
	report := methodaws.CloudFrontReport{
		AccountId:     aws.ToString(accountId),
		Distributions: []*methodaws.CloudFrontDistribution{},
		Errors:        []string{},
	}

	// Create a map to deduplicate distributions by ARN
	distributionsMap := make(map[string]*methodaws.CloudFrontDistribution)

	// loop through the regions and enumerate the cloudfront distributions
	for _, region := range regions {
		r, err := EnumerateCloudFrontForRegion(ctx, cfg, region)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Error in region %s: %s", region, err.Error()))
			continue
		}
		if r != nil && r.Distributions != nil {
			// Add each distribution to the map using ARN as key in order to deduplicate distributions
			for _, dist := range r.Distributions {
				distributionsMap[dist.Arn] = dist
			}
		}
	}

	// Convert map back to slice for the report
	for _, dist := range distributionsMap {
		report.Distributions = append(report.Distributions, dist)
	}

	return &report, nil
}
