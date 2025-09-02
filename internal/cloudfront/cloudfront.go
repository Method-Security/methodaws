package cloudfront

import (
	// Standard
	"context"
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateCloudFront(ctx context.Context, awsConfig aws.Config, config cloudfrontfern.CloudFrontEnumerateConfig) *cloudfrontfern.CloudFrontEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting CloudFront enumeration (global service)",
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &cloudfrontfern.CloudFrontEnumerateReport{
		Config: &config,
		Result: &cloudfrontfern.CloudFrontEnumerateResult{},
	}

	// CloudFront is a global service, always use us-east-1
	distributions, errors := enumerateCloudFrontDistributions(ctx, awsConfig)

	if len(errors) > 0 {
		log.Warn("Errors occurred while enumerating CloudFront distributions",
			svc1log.SafeParam("errorCount", len(errors)))
		report.Errors = errors
	}

	if len(distributions) > 0 {
		report.Result.Distributions = distributions
	}

	log.Info("Completed CloudFront enumeration",
		svc1log.SafeParam("totalDistributions", len(distributions)),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}

func enumerateCloudFrontDistributions(ctx context.Context, awsConfig aws.Config) ([]*cloudfrontfern.CloudFrontDistribution, []string) {
	log := svc1log.FromContext(ctx)
	// CloudFront is a global service, always use us-east-1
	awsConfig.Region = "us-east-1"

	cloudfrontClient := cloudfront.NewFromConfig(awsConfig)
	var errors []string

	log.Info("Listing CloudFront distributions from global endpoint")

	// List CloudFront distributions
	distributions, err := listCloudFrontDistributions(ctx, cloudfrontClient)
	if err != nil {
		errorMsg := "Failed to list CloudFront distributions: " + err.Error()
		log.Error("Error listing CloudFront distributions", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, errorMsg)
		return nil, errors
	}

	log.Info("Successfully listed CloudFront distributions", svc1log.SafeParam("count", len(distributions)))

	var cloudFrontDistributions []*cloudfrontfern.CloudFrontDistribution
	for _, dist := range distributions {
		cloudFrontDistribution := transformDistributionToFern(dist)
		cloudFrontDistributions = append(cloudFrontDistributions, cloudFrontDistribution)
	}

	return cloudFrontDistributions, errors
}

func listCloudFrontDistributions(ctx context.Context, cloudfrontClient *cloudfront.Client) ([]types.DistributionSummary, error) {
	var distributions []types.DistributionSummary
	paginator := cloudfront.NewListDistributionsPaginator(cloudfrontClient, &cloudfront.ListDistributionsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		if page.DistributionList != nil {
			distributions = append(distributions, page.DistributionList.Items...)
		}
	}

	return distributions, nil
}

func transformDistributionToFern(dist types.DistributionSummary) *cloudfrontfern.CloudFrontDistribution {
	// Transform origins
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.Origins != nil {
		for _, origin := range dist.Origins.Items {
			fernOrigin := &cloudfrontfern.CloudFrontDistributionOrigin{}
			if origin.DomainName != nil {
				fernOrigin.DomainName = *origin.DomainName
			}
			if origin.Id != nil {
				fernOrigin.Id = *origin.Id
			}
			origins = append(origins, fernOrigin)
		}
	}

	// Check that the comment exists, avoid passing back an empty string
	var comment *string
	if dist.Comment != nil && len(*dist.Comment) > 0 {
		comment = dist.Comment
	}

	// Check CDN enabled status
	var status cloudfrontfern.CloudFrontDistributionStatus = cloudfrontfern.CloudFrontDistributionStatusEnabled
	if dist.Enabled != nil && !*dist.Enabled {
		status = cloudfrontfern.CloudFrontDistributionStatusDisabled
	}

	return &cloudfrontfern.CloudFrontDistribution{
		Arn:        aws.ToString(dist.ARN),
		DomainName: aws.ToString(dist.DomainName),
		Comment:    comment,
		Origins:    origins,
		Status:     status,
	}
}
