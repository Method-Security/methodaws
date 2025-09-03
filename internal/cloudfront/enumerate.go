package cloudfront

import (
	// Standard
	"context"
	"fmt"
	"regexp"
	"strings"

	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateCloudFront(ctx context.Context, awsConfig aws.Config, config cloudfrontfern.CloudFrontEnumerateConfig) *cloudfrontfern.CloudFrontEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting CloudFront enumeration (global service)",
		svc1log.SafeParam("accountID", config.AccountId))

	// Initialize report
	report := &cloudfrontfern.CloudFrontEnumerateReport{
		Config: &config,
		Result: &cloudfrontfern.CloudFrontEnumerateResult{},
	}

	// CloudFront is a global service, always use us-east-1
	distributions, errors := enumerateCloudFrontDistributions(ctx, awsConfig, config)

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

func enumerateCloudFrontDistributions(ctx context.Context, awsConfig aws.Config, config cloudfrontfern.CloudFrontEnumerateConfig) ([]*cloudfrontfern.CloudFrontDistribution, []string) {
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
		// Get full distribution details for each distribution
		fullDistribution, err := getDistributionDetails(ctx, cloudfrontClient, *dist.Id)
		if err != nil {
			errorMsg := "Failed to get distribution details for " + *dist.Id + ": " + err.Error()
			log.Error("Error getting distribution details",
				svc1log.SafeParam("distributionId", *dist.Id),
				svc1log.SafeParam("error", err.Error()))
			errors = append(errors, errorMsg)
			// Fall back to using summary data
			cloudFrontDistribution := transformDistributionSummaryToFern(ctx, awsConfig, dist, config.AccountId)
			cloudFrontDistributions = append(cloudFrontDistributions, cloudFrontDistribution)
			continue
		}

		cloudFrontDistribution := transformDistributionToFern(ctx, awsConfig, *fullDistribution, config.AccountId)
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

func getDistributionDetails(ctx context.Context, cloudfrontClient *cloudfront.Client, distributionID string) (*types.Distribution, error) {
	input := &cloudfront.GetDistributionInput{
		Id: &distributionID,
	}

	result, err := cloudfrontClient.GetDistribution(ctx, input)
	if err != nil {
		return nil, err
	}

	return result.Distribution, nil
}

func classifyOriginType(domainName string) cloudfrontfern.CloudFrontOriginType {
	// S3 bucket patterns
	if strings.Contains(domainName, ".s3.amazonaws.com") ||
		strings.Contains(domainName, ".s3.") ||
		strings.HasSuffix(domainName, ".s3-website-us-east-1.amazonaws.com") ||
		strings.HasSuffix(domainName, ".s3-website.amazonaws.com") ||
		strings.Contains(domainName, ".s3-website") {
		return cloudfrontfern.CloudFrontOriginTypeS3
	}

	// Load balancer patterns
	if strings.Contains(domainName, ".elb.amazonaws.com") ||
		strings.Contains(domainName, ".elasticloadbalancing.") {
		return cloudfrontfern.CloudFrontOriginTypeApplicationLoadBalancer
	}

	// EC2 instance patterns
	if strings.Contains(domainName, ".compute.amazonaws.com") ||
		strings.Contains(domainName, ".compute-1.amazonaws.com") ||
		strings.Contains(domainName, "ec2-") {
		return cloudfrontfern.CloudFrontOriginTypeEc2
	}

	// VPC origin pattern (new feature)
	if strings.Contains(domainName, ".vpc-endpoint") {
		return cloudfrontfern.CloudFrontOriginTypeVpcOrigin
	}

	// API Gateway patterns: <api-id>.execute-api.<region>.amazonaws.com
	if strings.Contains(domainName, ".execute-api.") && strings.Contains(domainName, ".amazonaws.com") {
		return cloudfrontfern.CloudFrontOriginTypeApiGateway
	}

	// Default to unknown for anything else
	return cloudfrontfern.CloudFrontOriginTypeUnknown
}

// ARN resolution functions for different origin types
func resolveOriginArn(ctx context.Context, awsConfig aws.Config, domainName string, originType cloudfrontfern.CloudFrontOriginType, accountID string) (string, error) {
	log := svc1log.FromContext(ctx)

	switch originType {
	case cloudfrontfern.CloudFrontOriginTypeS3:
		return resolveS3BucketArn(domainName)
	case cloudfrontfern.CloudFrontOriginTypeApplicationLoadBalancer:
		return resolveLoadBalancerArn(ctx, awsConfig, domainName, accountID)
	case cloudfrontfern.CloudFrontOriginTypeEc2:
		return resolveEc2InstanceArn(ctx, awsConfig, domainName, accountID)
	case cloudfrontfern.CloudFrontOriginTypeApiGateway:
		return resolveAPIGatewayArn(domainName, accountID)
	default:
		log.Debug("No ARN resolution available for origin type",
			svc1log.SafeParam("originType", string(originType)),
			svc1log.SafeParam("domainName", domainName))
		return "", nil
	}
}

func resolveS3BucketArn(domainName string) (string, error) {
	// Extract bucket name from different S3 domain patterns
	var bucketName string

	if strings.Contains(domainName, ".s3.amazonaws.com") {
		// Pattern: bucket-name.s3.amazonaws.com
		bucketName = strings.Split(domainName, ".s3.amazonaws.com")[0]
	} else if strings.Contains(domainName, ".s3.") {
		// Pattern: bucket-name.s3.region.amazonaws.com
		bucketName = strings.Split(domainName, ".s3.")[0]
	} else if strings.Contains(domainName, ".s3-website") {
		// S3 website endpoints: bucket-name.s3-website-region.amazonaws.com
		bucketName = strings.Split(domainName, ".s3-website")[0]
	} else {
		return "", fmt.Errorf("unable to extract bucket name from domain: %s", domainName)
	}

	// S3 bucket ARNs don't include account ID
	return fmt.Sprintf("arn:aws:s3:::%s", bucketName), nil
}

func resolveLoadBalancerArn(ctx context.Context, awsConfig aws.Config, domainName string, accountID string) (string, error) {
	log := svc1log.FromContext(ctx)

	// Try ALB/NLB first (v2)
	if arn, err := resolveALBArn(ctx, awsConfig, domainName); err == nil && arn != "" {
		return arn, nil
	}

	// Fall back to Classic Load Balancer (v1)
	if arn, err := resolveClassicELBArn(ctx, awsConfig, domainName, accountID); err == nil && arn != "" {
		return arn, nil
	}

	log.Debug("Could not resolve load balancer ARN", svc1log.SafeParam("domainName", domainName))
	return "", fmt.Errorf("could not resolve load balancer ARN for domain: %s", domainName)
}

func resolveALBArn(ctx context.Context, awsConfig aws.Config, domainName string) (string, error) {
	// Extract region from ELB domain name
	region, err := extractRegionFromELBDomain(domainName)
	if err != nil {
		return "", err
	}

	awsConfig.Region = region
	elbv2Client := elasticloadbalancingv2.NewFromConfig(awsConfig)

	// List all load balancers and find the one matching the domain name
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(elbv2Client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}

		for _, lb := range page.LoadBalancers {
			if lb.DNSName != nil && *lb.DNSName == domainName {
				return aws.ToString(lb.LoadBalancerArn), nil
			}
		}
	}

	return "", fmt.Errorf("ALB/NLB not found for domain: %s", domainName)
}

func resolveClassicELBArn(ctx context.Context, awsConfig aws.Config, domainName string, accountID string) (string, error) {
	// Extract region from ELB domain name
	region, err := extractRegionFromELBDomain(domainName)
	if err != nil {
		return "", err
	}

	awsConfig.Region = region
	elbClient := elasticloadbalancing.NewFromConfig(awsConfig)

	// List all classic load balancers
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(elbClient, &elasticloadbalancing.DescribeLoadBalancersInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}

		for _, lb := range page.LoadBalancerDescriptions {
			if lb.DNSName != nil && *lb.DNSName == domainName {
				// Construct Classic ELB ARN manually as it's not provided in the response
				return fmt.Sprintf("arn:aws:elasticloadbalancing:%s:%s:loadbalancer/%s",
					region, accountID, aws.ToString(lb.LoadBalancerName)), nil
			}
		}
	}

	return "", fmt.Errorf("classic ELB not found for domain: %s", domainName)
}

func resolveEc2InstanceArn(ctx context.Context, awsConfig aws.Config, domainName string, accountID string) (string, error) {
	// Extract region from EC2 domain name
	region, err := extractRegionFromEC2Domain(domainName)
	if err != nil {
		return "", err
	}

	awsConfig.Region = region
	ec2Client := ec2.NewFromConfig(awsConfig)

	// List instances and find the one matching the domain name
	paginator := ec2.NewDescribeInstancesPaginator(ec2Client, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.PublicDnsName != nil && *instance.PublicDnsName == domainName {
					return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s",
						region, accountID, aws.ToString(instance.InstanceId)), nil
				}
			}
		}
	}

	return "", fmt.Errorf("EC2 instance not found for domain: %s", domainName)
}

func resolveAPIGatewayArn(domainName string, accountID string) (string, error) {
	// Extract API ID and region from API Gateway domain pattern
	// Pattern: <api-id>.execute-api.<region>.amazonaws.com
	if !strings.Contains(domainName, ".execute-api.") || !strings.Contains(domainName, ".amazonaws.com") {
		return "", fmt.Errorf("invalid API Gateway domain pattern: %s", domainName)
	}

	// Extract API ID (everything before the first dot)
	parts := strings.Split(domainName, ".")
	if len(parts) < 4 {
		return "", fmt.Errorf("unable to extract API ID from domain: %s", domainName)
	}
	apiId := parts[0]

	// Extract region (the part between execute-api and amazonaws)
	region, err := extractRegionFromAPIGatewayDomain(domainName)
	if err != nil {
		return "", err
	}

	// API Gateway REST API ARN format: arn:aws:apigateway:region::restapis/api-id
	return fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s", region, apiId), nil
}

func extractRegionFromAPIGatewayDomain(domainName string) (string, error) {
	// API Gateway domain pattern: <api-id>.execute-api.<region>.amazonaws.com
	re := regexp.MustCompile(`[^.]+\.execute-api\.([^.]+)\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from API Gateway domain: %s", domainName)
	}
	return matches[1], nil
}

func extractRegionFromELBDomain(domainName string) (string, error) {
	// ELB domain pattern: name-123456789.region.elb.amazonaws.com
	re := regexp.MustCompile(`[^.]+\.([^.]+)\.elb\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from ELB domain: %s", domainName)
	}
	return matches[1], nil
}

func extractRegionFromEC2Domain(domainName string) (string, error) {
	// EC2 domain pattern: ec2-x-x-x-x.region.compute.amazonaws.com
	re := regexp.MustCompile(`ec2-[^.]+\.([^.]+)\.compute\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from EC2 domain: %s", domainName)
	}
	return matches[1], nil
}

func transformDistributionToFern(ctx context.Context, awsConfig aws.Config, dist types.Distribution, accountID string) *cloudfrontfern.CloudFrontDistribution {
	// Transform origins with enhanced details
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.DistributionConfig != nil && dist.DistributionConfig.Origins != nil {
		for _, origin := range dist.DistributionConfig.Origins.Items {
			fernOrigin := &cloudfrontfern.CloudFrontDistributionOrigin{}

			if origin.DomainName != nil {
				fernOrigin.DomainName = *origin.DomainName
				fernOrigin.OriginType = classifyOriginType(*origin.DomainName)

				// Attempt to resolve ARN for the origin
				if arn, err := resolveOriginArn(ctx, awsConfig, *origin.DomainName, fernOrigin.OriginType, accountID); err == nil && arn != "" {
					fernOrigin.OriginArn = &arn
				}
			}

			if origin.Id != nil {
				fernOrigin.Id = *origin.Id
			}

			if origin.OriginPath != nil && len(*origin.OriginPath) > 0 {
				fernOrigin.Path = origin.OriginPath
			}

			// Custom headers
			if origin.CustomOriginConfig != nil {
				timeout := origin.CustomOriginConfig.OriginReadTimeout
				timeoutInt := int(*timeout)
				if origin.CustomOriginConfig.OriginKeepaliveTimeout != nil {
					fernOrigin.ConnectionTimeout = &timeoutInt
				}
			}

			// S3 website check
			if origin.S3OriginConfig != nil {
				isS3Website := false
				fernOrigin.IsS3Website = &isS3Website
			}

			// Custom headers
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

			origins = append(origins, fernOrigin)
		}
	}

	// Check that the comment exists, avoid passing back an empty string
	var comment *string
	if dist.DistributionConfig != nil && dist.DistributionConfig.Comment != nil && len(*dist.DistributionConfig.Comment) > 0 {
		comment = dist.DistributionConfig.Comment
	}

	// Check CDN enabled status
	var status cloudfrontfern.CloudFrontDistributionStatus = cloudfrontfern.CloudFrontDistributionStatusEnabled
	if dist.DistributionConfig != nil && dist.DistributionConfig.Enabled != nil && !*dist.DistributionConfig.Enabled {
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

// Fallback transformation for when we only have DistributionSummary
func transformDistributionSummaryToFern(ctx context.Context, awsConfig aws.Config, dist types.DistributionSummary, accountID string) *cloudfrontfern.CloudFrontDistribution {
	// Transform origins (limited info from summary)
	var origins []*cloudfrontfern.CloudFrontDistributionOrigin
	if dist.Origins != nil {
		for _, origin := range dist.Origins.Items {
			fernOrigin := &cloudfrontfern.CloudFrontDistributionOrigin{}

			if origin.DomainName != nil {
				fernOrigin.DomainName = *origin.DomainName
				fernOrigin.OriginType = classifyOriginType(*origin.DomainName)

				// Attempt to resolve ARN for the origin
				if arn, err := resolveOriginArn(ctx, awsConfig, *origin.DomainName, fernOrigin.OriginType, accountID); err == nil && arn != "" {
					fernOrigin.OriginArn = &arn
				}
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
