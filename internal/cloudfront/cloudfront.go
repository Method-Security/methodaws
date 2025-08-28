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
	log.Info("Starting CloudFront enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &cloudfrontfern.CloudFrontEnumerateReport{
		Config: &config,
		Result: &cloudfrontfern.CloudFrontEnumerateResult{},
	}

	var allDistributions []*cloudfrontfern.CloudFrontDistribution
	var allErrors []string

	// Create a map to deduplicate distributions by ARN
	distributionsMap := make(map[string]*cloudfrontfern.CloudFrontDistribution)

	for _, region := range config.Regions {
		log.Info("Processing CloudFront distributions in region", svc1log.SafeParam("region", region))
		distributions, errors := enumerateCloudFrontForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating CloudFront distributions in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		// Add each distribution to the map using ARN as key to deduplicate
		for _, dist := range distributions {
			distributionsMap[dist.Arn] = dist
		}
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed CloudFront distributions in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("distributionCount", len(distributions)))
	}

	// Convert map back to slice for the report
	for _, dist := range distributionsMap {
		allDistributions = append(allDistributions, dist)
	}

	// Marshal report
	if len(allDistributions) > 0 {
		report.Result.Distributions = allDistributions
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed CloudFront enumeration",
		svc1log.SafeParam("totalDistributions", len(allDistributions)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

func enumerateCloudFrontForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*cloudfrontfern.CloudFrontDistribution, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	cloudfrontClient := cloudfront.NewFromConfig(awsConfig)
	var errors []string

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
