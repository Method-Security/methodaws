package enumerate

import (
	// Standard
	"context"
	"strings"

	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

func classifyOriginType(domainName string) cloudfrontfern.CloudFrontResourceType {
	// S3 bucket patterns
	if strings.Contains(domainName, ".s3.amazonaws.com") ||
		strings.Contains(domainName, ".s3.") ||
		strings.HasSuffix(domainName, ".s3-website-us-east-1.amazonaws.com") ||
		strings.HasSuffix(domainName, ".s3-website.amazonaws.com") ||
		strings.Contains(domainName, ".s3-website") {
		return cloudfrontfern.CloudFrontResourceTypeS3
	}

	// Load balancer patterns
	if strings.Contains(domainName, ".elb.amazonaws.com") ||
		strings.Contains(domainName, ".elasticloadbalancing.") {
		return cloudfrontfern.CloudFrontResourceTypeApplicationLoadBalancer
	}

	// EC2 instance patterns
	if strings.Contains(domainName, ".compute.amazonaws.com") ||
		strings.Contains(domainName, ".compute-1.amazonaws.com") ||
		strings.Contains(domainName, "ec2-") {
		return cloudfrontfern.CloudFrontResourceTypeEc2
	}

	// VPC origin pattern (new feature)
	if strings.Contains(domainName, ".vpc-endpoint") {
		return cloudfrontfern.CloudFrontResourceTypeVpcOrigin
	}

	// API Gateway patterns: <api-id>.execute-api.<region>.amazonaws.com
	if strings.Contains(domainName, ".execute-api.") && strings.Contains(domainName, ".amazonaws.com") {
		return cloudfrontfern.CloudFrontResourceTypeApiGateway
	}

	// Default to unknown for anything else
	return cloudfrontfern.CloudFrontResourceTypeUnknown
}

// shouldResolveIdentifier determines whether identifier resolution makes sense for a given resource type
func shouldResolveIdentifier(resourceType cloudfrontfern.CloudFrontResourceType) bool {
	switch resourceType {
	case cloudfrontfern.CloudFrontResourceTypeS3,
		cloudfrontfern.CloudFrontResourceTypeApplicationLoadBalancer,
		cloudfrontfern.CloudFrontResourceTypeEc2,
		cloudfrontfern.CloudFrontResourceTypeApiGateway:
		return true
	case cloudfrontfern.CloudFrontResourceTypeVpcOrigin,
		cloudfrontfern.CloudFrontResourceTypeUnknown:
		return false
	default:
		return false
	}
}

// processOrigins converts AWS CloudFront origins to Fern format with identifier resolution
func processOrigins(ctx context.Context, awsConfig aws.Config, origins []types.Origin, accountID string) ([]*cloudfrontfern.CloudFrontDistributionOrigin, []string) {
	log := svc1log.FromContext(ctx)

	var fernOrigins []*cloudfrontfern.CloudFrontDistributionOrigin
	var errors []string

	for _, origin := range origins {
		if origin.Id == nil {
			log.Warn("Origin ID is nil for origin", svc1log.SafeParam("origin", origin))
			errors = append(errors, "Origin ID is nil")
			continue
		}
		fernOrigin := processOrigin(ctx, awsConfig, origin, accountID)
		fernOrigins = append(fernOrigins, fernOrigin)
	}

	return fernOrigins, errors
}

// processOrigin converts a single AWS CloudFront origin to Fern format
func processOrigin(ctx context.Context, awsConfig aws.Config, origin types.Origin, accountID string) *cloudfrontfern.CloudFrontDistributionOrigin {
	fernOrigin := &cloudfrontfern.CloudFrontDistributionOrigin{}

	if origin.DomainName != nil {
		fernOrigin.DomainName = *origin.DomainName
		fernOrigin.ResourceType = classifyOriginType(*origin.DomainName)
	}

	// Set basic origin ID as fallback
	if origin.Id != nil {
		fernOrigin.Id = *origin.Id
	}

	// Only attempt identifier resolution for resource types where it makes sense
	if origin.DomainName != nil && shouldResolveIdentifier(fernOrigin.ResourceType) {
		if identifier, err := resolveOriginIdentifier(ctx, awsConfig, *origin.DomainName, fernOrigin.ResourceType, accountID); err == nil && identifier != "" {
			fernOrigin.Id = identifier
		}
	}

	if origin.OriginPath != nil && len(*origin.OriginPath) > 0 {
		fernOrigin.Path = origin.OriginPath
	}

	// Process connection timeout
	if origin.CustomOriginConfig != nil {
		timeout := origin.CustomOriginConfig.OriginReadTimeout
		timeoutInt := int(*timeout)
		if origin.CustomOriginConfig.OriginKeepaliveTimeout != nil {
			fernOrigin.ConnectionTimeout = &timeoutInt
		}
	}

	// Process custom headers
	if origin.CustomHeaders != nil {
		var customHeaders []string
		for _, header := range origin.CustomHeaders.Items {
			if header.HeaderName != nil {
				customHeaders = append(customHeaders, *header.HeaderName)
			}
		}
		if len(customHeaders) > 0 {
			fernOrigin.CustomHeaders = customHeaders
		}
	}

	return fernOrigin
}
