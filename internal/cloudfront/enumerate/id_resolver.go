package enumerate

import (
	// Standard
	"context"
	"fmt"
	"regexp"
	"strings"

	// Internal
	// Generated
	cloudfrontfern "github.com/Method-Security/methodaws/generated/go/cloudfront"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// resolveOriginIdentifier resolves the most appropriate identifier for a CloudFront origin:
// - S3: bucket name (ID)
// - ALB/NLB: Load Balancer ARN (ELBv2)
// - Classic ELB: Load Balancer name (ID)
// - EC2: instance ID
// - API Gateway: API ID
func resolveOriginIdentifier(ctx context.Context, awsConfig aws.Config, domainName string, originType cloudfrontfern.CloudFrontResourceType, accountID string) (string, error) {
	log := svc1log.FromContext(ctx)

	switch originType {
	case cloudfrontfern.CloudFrontResourceTypeS3:
		return resolveS3BucketID(domainName)
	case cloudfrontfern.CloudFrontResourceTypeApplicationLoadBalancer:
		return resolveELBv2ARN(ctx, awsConfig, domainName)
	case cloudfrontfern.CloudFrontResourceTypeEc2:
		return resolveEC2InstanceID(ctx, awsConfig, domainName)
	case cloudfrontfern.CloudFrontResourceTypeApiGateway:
		return resolveAPIGatewayID(domainName)
	default:
		log.Debug("No identifier resolution available for origin type",
			svc1log.SafeParam("originType", string(originType)),
			svc1log.SafeParam("domainName", domainName))
		return "", nil
	}
}

// --- S3: return bucket name (ID) ---
func resolveS3BucketID(domainName string) (string, error) {
	// Extract bucket name from common S3 endpoint forms
	var bucket string
	switch {
	case strings.Contains(domainName, ".s3.amazonaws.com"):
		// bucket.s3.amazonaws.com
		bucket = strings.Split(domainName, ".s3.amazonaws.com")[0]
	case strings.Contains(domainName, ".s3."):
		// bucket.s3.<region>.amazonaws.com
		bucket = strings.Split(domainName, ".s3.")[0]
	case strings.Contains(domainName, ".s3-website"):
		// bucket.s3-website-<region>.amazonaws.com
		bucket = strings.Split(domainName, ".s3-website")[0]
	default:
		return "", fmt.Errorf("unable to extract S3 bucket from domain: %s", domainName)
	}
	return bucket, nil
}

// --- ELBv2 (ALB/NLB/GWLB): return ARN ---
func resolveELBv2ARN(ctx context.Context, awsConfig aws.Config, domainName string) (string, error) {
	region, err := extractRegionFromELBDomain(domainName)
	if err != nil {
		return "", err
	}
	awsConfig.Region = region
	elbv2Client := elasticloadbalancingv2.NewFromConfig(awsConfig)

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
	return "", fmt.Errorf("ELBv2 not found for domain: %s", domainName)
}

// --- EC2: return instance ID ---
func resolveEC2InstanceID(ctx context.Context, awsConfig aws.Config, domainName string) (string, error) {
	region, err := extractRegionFromEC2Domain(domainName)
	if err != nil {
		return "", err
	}
	awsConfig.Region = region
	ec2Client := ec2.NewFromConfig(awsConfig)

	paginator := ec2.NewDescribeInstancesPaginator(ec2Client, &ec2.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return "", err
		}
		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				if instance.PublicDnsName != nil && *instance.PublicDnsName == domainName {
					return aws.ToString(instance.InstanceId), nil
				}
			}
		}
	}
	return "", fmt.Errorf("EC2 instance not found for domain: %s", domainName)
}

// --- API Gateway: return API ID ---
func resolveAPIGatewayID(domainName string) (string, error) {
	// <api-id>.execute-api.<region>.amazonaws.com
	if !strings.Contains(domainName, ".execute-api.") || !strings.Contains(domainName, ".amazonaws.com") {
		return "", fmt.Errorf("invalid API Gateway domain pattern: %s", domainName)
	}
	parts := strings.Split(domainName, ".")
	if len(parts) < 4 {
		return "", fmt.Errorf("unable to extract API ID from domain: %s", domainName)
	}
	apiID := parts[0]
	// Optionally validate region:
	if _, err := extractRegionFromAPIGatewayDomain(domainName); err != nil {
		return "", err
	}
	return apiID, nil
}

// ---------------------
// Region extractors
// ---------------------

func extractRegionFromAPIGatewayDomain(domainName string) (string, error) {
	re := regexp.MustCompile(`[^.]+\.execute-api\.([^.]+)\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from API Gateway domain: %s", domainName)
	}
	return matches[1], nil
}

func extractRegionFromELBDomain(domainName string) (string, error) {
	re := regexp.MustCompile(`[^.]+\.([^.]+)\.elb\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from ELB domain: %s", domainName)
	}
	return matches[1], nil
}

func extractRegionFromEC2Domain(domainName string) (string, error) {
	re := regexp.MustCompile(`ec2-[^.]+\.([^.]+)\.compute\.amazonaws\.com`)
	matches := re.FindStringSubmatch(domainName)
	if len(matches) < 2 {
		return "", fmt.Errorf("could not extract region from EC2 domain: %s", domainName)
	}
	return matches[1], nil
}
