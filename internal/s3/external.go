package s3

import (
	"context"
	"fmt"
	"strings"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

// isNonStandardS3URL checks if the URL follows standard S3 URL patterns
func isNonStandardS3URL(url string) bool {
	return !strings.Contains(url, "amazonaws.com") || !strings.Contains(url, "s3")
}

// parseBucketURL extracts bucket name and potentially region from S3 URL
// Handles formats like:
// - https://bucket-name.s3.region.amazonaws.com
// - https://s3.region.amazonaws.com/bucket-name
// - bucket-name.s3.region.amazonaws.com
func parseBucketURL(bucketURL string) (bucketName string, region string) {
	// Remove protocol if present
	bucketURL = strings.TrimPrefix(bucketURL, "https://")
	bucketURL = strings.TrimPrefix(bucketURL, "http://")

	// Handle non-standard URLs
	if isNonStandardS3URL(bucketURL) {
		return bucketURL, ""
	}

	// Parse standard S3 URLs
	if strings.Contains(bucketURL, "/") {
		// Format: s3.region.amazonaws.com/bucket-name
		parts := strings.SplitN(bucketURL, "/", 2)
		bucketName = parts[1]
		hostParts := strings.Split(parts[0], ".")
		if len(hostParts) >= 4 && hostParts[0] == "s3" {
			region = hostParts[1]
		}
	} else {
		// Format: bucket-name.s3.region.amazonaws.com
		parts := strings.Split(bucketURL, ".")
		if len(parts) >= 5 {
			bucketName = parts[0]
			if parts[1] == "s3" {
				region = parts[2]
			}
		}
	}

	// Clean up bucket name
	bucketName = strings.Split(bucketName, "?")[0]
	bucketName = strings.TrimRight(bucketName, "/")

	return bucketName, region
}

// bucketExists checks if a bucket exists and is accessible
func bucketExists(ctx context.Context, region string, bucketName string) (bool, error) {
	// Create a custom AWS config with anonymous credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		return false, fmt.Errorf("error loading AWS config: %v", err)
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Try HeadBucket to check existence
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "NotFound", "NoSuchBucket":
				return false, nil
			case "Forbidden", "AccessDenied":
				return true, nil // Bucket exists but we don't have access
			default:
				return false, fmt.Errorf("error checking bucket: %v", err)
			}
		}
		return false, fmt.Errorf("error checking bucket: %v", err)
	}

	return true, nil
}

// listBucketContents attempts to list objects in the bucket
func listBucketContents(ctx context.Context, client *s3.Client, bucketName string) ([]*methodaws.S3ObjectDetails, error) {
	maxKeys := int32(100) // Limit the number of objects to list
	directoryContents := []*methodaws.S3ObjectDetails{}

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})

	// Get first page only to avoid overwhelming the API
	page, err := paginator.NextPage(ctx)
	if err != nil {
		return nil, fmt.Errorf("error listing bucket contents: %v", err)
	}

	for _, object := range page.Contents {
		var size int
		if object.Size != nil {
			size = int(*object.Size)
		}

		details := &methodaws.S3ObjectDetails{
			Key:          *object.Key,
			LastModified: object.LastModified,
			Size:         &size,
		}

		if object.Owner != nil {
			details.OwnerId = object.Owner.ID
			details.OwnerName = object.Owner.DisplayName
		}

		directoryContents = append(directoryContents, details)
	}

	return directoryContents, nil
}

// checkListingAllowed checks if listing objects is allowed on a bucket
func checkListingAllowed(ctx context.Context, client *s3.Client, bucketName string) bool {
	maxKeys := int32(1)
	_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})
	return err == nil
}

// checkAnonymousReadAllowed checks if anonymous read is allowed on a bucket
func checkAnonymousReadAllowed(ctx context.Context, client *s3.Client, bucketName string, directoryContents []*methodaws.S3ObjectDetails) bool {
	if len(directoryContents) > 0 {
		_, err := client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(directoryContents[0].Key),
		})
		return err == nil
	}
	return false
}

// checkPolicy checks the bucket policy
func checkPolicy(ctx context.Context, client *s3.Client, bucketName string) (string, error) {
	policyOutput, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && policyOutput.Policy != nil {
		return *policyOutput.Policy, nil
	}
	return "", fmt.Errorf("error getting bucket policy: %v", err)
}

// checkACL checks the bucket ACL
func checkACL(ctx context.Context, client *s3.Client, bucketName string) ([]*methodaws.S3BucketAcl, *string, *string, error) {
	acls := []*methodaws.S3BucketAcl{}

	output, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	// Extract owner information
	var ownerID, ownerName *string
	if output.Owner != nil {
		ownerID = output.Owner.ID
		ownerName = output.Owner.DisplayName
	}

	for _, grant := range output.Grants {
		if grant.Grantee.URI != nil {
			acls = append(acls, &methodaws.S3BucketAcl{
				GranteeUri: *grant.Grantee.URI,
				Permission: string(grant.Permission),
			})
		}
	}

	return acls, ownerID, ownerName, nil
}

// ExternalEnumerateS3Region enumerates a single public facing S3 bucket in a specific region
func ExternalEnumerateS3Region(ctx context.Context, report methodaws.ExternalS3Report, bucketName string, region string) methodaws.ExternalS3Report {
	// Create a custom AWS config with anonymous credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("error loading AWS config: %v", err))
		return report
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Initialize bucket info
	externalBucket := methodaws.ExternalBucket{
		Name:   bucketName,
		Region: region,
		Url:    fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, region),
	}

	// Check if listing is allowed and get directory contents
	externalBucket.AllowDirectoryListing = checkListingAllowed(ctx, client, bucketName)
	if externalBucket.AllowDirectoryListing {
		directoryContents, err := listBucketContents(ctx, client, bucketName)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("error listing bucket contents: %v", err))
		} else {
			externalBucket.DirectoryContents = directoryContents
			// Check anonymous read access if we found any objects
			externalBucket.AllowAnonymousRead = checkAnonymousReadAllowed(ctx, client, bucketName, directoryContents)
		}
	}

	// Check bucket policy
	policy, err := checkPolicy(ctx, client, bucketName)
	if err == nil {
		externalBucket.Policy = &policy
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("Error getting bucket policy: %v", err))
	}

	// Check bucket ACL and get owner information
	acls, ownerID, ownerName, err := checkACL(ctx, client, bucketName)
	if err == nil {
		externalBucket.Acls = acls
		externalBucket.OwnerId = ownerID
		externalBucket.OwnerName = ownerName
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("Error getting bucket ACL: %v", err))
	}

	report.ExternalBuckets = append(report.ExternalBuckets, &externalBucket)
	return report
}

// ExternalEnumerateS3 attempts to enumerate a public facing S3 bucket with no credentials
func ExternalEnumerateS3(ctx context.Context, bucketURL string, regions []string) methodaws.ExternalS3Report {
	report := methodaws.ExternalS3Report{
		ExternalBuckets: []*methodaws.ExternalBucket{},
		Errors:          []string{},
	}

	// Parse the bucket URL to get name and potentially region
	bucketName, urlRegion := parseBucketURL(bucketURL)

	// If we got a region from the URL, only check that region
	regionsToCheck := regions
	if urlRegion != "" {
		regionsToCheck = []string{urlRegion}
	}

	// For non-standard URLs, try the default region first
	if isNonStandardS3URL(bucketURL) {
		regionsToCheck = append([]string{"us-east-1"}, regionsToCheck...)
	}

	bucketFound := false
	for _, region := range regionsToCheck {
		exists, err := bucketExists(ctx, region, bucketName)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("Error checking bucket in region %s: %v", region, err))
			continue
		}
		if exists {
			report = ExternalEnumerateS3Region(ctx, report, bucketName, region)
			bucketFound = true
			break
		}
	}

	if !bucketFound {
		report.Errors = append(report.Errors, "Bucket not found in any of the specified regions")
	}

	return report
}
