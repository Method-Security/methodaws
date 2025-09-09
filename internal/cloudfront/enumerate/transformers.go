package enumerate

import (
	// Standard
	"context"
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// extractDistributionComment safely extracts comment from distribution config
func extractDistributionComment(comment *string) *string {
	if comment != nil && len(*comment) > 0 {
		return comment
	}
	return nil
}

// extractDistributionStatus determines the distribution status
func extractDistributionStatus(enabled *bool) cloudfrontfern.CloudFrontDistributionStatus {
	if enabled != nil && !*enabled {
		return cloudfrontfern.CloudFrontDistributionStatusDisabled
	}
	return cloudfrontfern.CloudFrontDistributionStatusEnabled
}

func transformDistributionToFern(ctx context.Context, awsConfig aws.Config, dist types.Distribution, accountID string) *cloudfrontfern.CloudFrontDistribution {
	// Transform origins with enhanced details
	if dist.Id == nil {
		return nil
	}
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.DistributionConfig != nil && dist.DistributionConfig.Origins != nil {
		origins = processOrigins(ctx, awsConfig, dist.DistributionConfig.Origins.Items, accountID)
	}

	// Extract comment and status using helper functions
	var comment *string
	var status cloudfrontfern.CloudFrontDistributionStatus
	if dist.DistributionConfig != nil {
		comment = extractDistributionComment(dist.DistributionConfig.Comment)
		status = extractDistributionStatus(dist.DistributionConfig.Enabled)
	} else {
		status = cloudfrontfern.CloudFrontDistributionStatusEnabled
	}

	return &cloudfrontfern.CloudFrontDistribution{
		Id:         aws.ToString(dist.Id),
		Arn:        dist.ARN,
		DomainName: dist.DomainName,
		Comment:    comment,
		Origins:    origins,
		Status:     &status,
	}
}

// Fallback transformation for when we only have DistributionSummary
func transformDistributionSummaryToFern(ctx context.Context, awsConfig aws.Config, dist types.DistributionSummary, accountID string) *cloudfrontfern.CloudFrontDistribution {
	// Transform origins (limited info from summary)
	if dist.Id == nil {
		return nil
	}
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.Origins != nil {
		origins = processOrigins(ctx, awsConfig, dist.Origins.Items, accountID)
	}

	// Extract comment and status using helper functions
	comment := extractDistributionComment(dist.Comment)
	status := extractDistributionStatus(dist.Enabled)

	return &cloudfrontfern.CloudFrontDistribution{
		Id:         aws.ToString(dist.Id),
		Arn:        dist.ARN,
		DomainName: dist.DomainName,
		Comment:    comment,
		Origins:    origins,
		Status:     &status,
	}
}
