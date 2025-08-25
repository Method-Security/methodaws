package s3

import (
	// Standard
	"context"
	"fmt"
	"strings"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"

	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
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
	// Clean Bucket URL
	// Remove protocol if present
	bucketURL = strings.TrimPrefix(bucketURL, "https://")
	bucketURL = strings.TrimPrefix(bucketURL, "http://")
	bucketURL = strings.Split(bucketURL, ":")[0]

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
	log := svc1log.FromContext(ctx)

	// Create a custom AWS config with anonymous credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		log.Error("Failed to load AWS config for bucket existence check",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return false, fmt.Errorf("error loading AWS config: %v", err)
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Try HeadBucket to check existence
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		errStr := err.Error()

		if strings.Contains(errStr, "NotFound") || strings.Contains(errStr, "NoSuchBucket") {
			log.Info("Bucket not found",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			return false, nil
		}

		if strings.Contains(errStr, "Forbidden") || strings.Contains(errStr, "AccessDenied") {
			log.Warn("Bucket exists but access is denied",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			return true, nil // Bucket exists but we don't have access
		}

		log.Error("Error checking bucket existence",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return false, fmt.Errorf("error checking bucket: %v", err)
	}

	return true, nil
}

// listBucketContents attempts to list objects in the bucket
func listBucketContents(ctx context.Context, client *s3.Client, bucketName string) ([]*s3fern.S3ObjectDetails, error) {
	log := svc1log.FromContext(ctx)
	maxKeys := int32(100) // Limit the number of objects to list
	directoryContents := []*s3fern.S3ObjectDetails{}

	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket:     aws.String(bucketName),
		MaxKeys:    &maxKeys,
		FetchOwner: aws.Bool(true),
	})

	// Get first page only to avoid overwhelming the API
	page, err := paginator.NextPage(ctx)
	if err != nil {
		log.Error("Failed to list bucket contents",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		return nil, fmt.Errorf("error listing bucket contents: %v", err)
	}

	for _, object := range page.Contents {
		var size int
		if object.Size != nil {
			size = int(*object.Size)
		}

		details := &s3fern.S3ObjectDetails{
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
func checkAnonymousReadAllowed(ctx context.Context, client *s3.Client, bucketName string, directoryContents []*s3fern.S3ObjectDetails) bool {
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
func checkACL(ctx context.Context, client *s3.Client, bucketName string) ([]*s3fern.S3BucketAcl, *string, *string, error) {
	acls := []*s3fern.S3BucketAcl{}

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
			acls = append(acls, &s3fern.S3BucketAcl{
				GranteeUri: *grant.Grantee.URI,
				Permission: string(grant.Permission),
			})
		}
	}

	return acls, ownerID, ownerName, nil
}

// ExternalEnumerateS3Region enumerates a single public facing S3 bucket in a specific region
func externalEnumerateS3Region(ctx context.Context, bucketURL string, bucketName string, region string) (*s3fern.ExternalS3BucketResult, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Starting external S3 bucket enumeration",
		svc1log.SafeParam("bucketName", bucketName),
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("bucketURL", bucketURL))

	// Initialize variables
	report := s3fern.ExternalS3BucketResult{}
	externalBucket := s3fern.ExternalBucket{
		Name:   bucketName,
		Region: region,
		Url:    bucketURL,
	}
	errors := []string{}

	// Create a custom AWS config with anonymous credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	if err != nil {
		log.Error("Failed to load AWS config for external enumeration",
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("error loading AWS config: %v", err))
		return nil, errors
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// Check if listing is allowed and get directory contents
	externalBucket.AllowDirectoryListing = checkListingAllowed(ctx, client, bucketName)
	if externalBucket.AllowDirectoryListing {
		directoryContents, err := listBucketContents(ctx, client, bucketName)
		if err != nil {
			errors = append(errors, fmt.Sprintf("error listing bucket contents: %v", err))
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
		log.Warn("Failed to get bucket policy",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("Error getting bucket policy: %v", err))
	}

	// Check bucket ACL and get owner information
	acls, ownerID, ownerName, err := checkACL(ctx, client, bucketName)
	if err == nil {
		externalBucket.Acls = acls
		externalBucket.OwnerId = ownerID
		externalBucket.OwnerName = ownerName
	} else {
		log.Warn("Failed to get bucket ACL",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.Stacktrace(err))
		errors = append(errors, fmt.Sprintf("Error getting bucket ACL: %v", err))
	}

	report.ExternalBuckets = append(report.ExternalBuckets, &externalBucket)

	log.Info("External S3 bucket enumeration completed",
		svc1log.SafeParam("bucketName", bucketName),
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("allowDirectoryListing", externalBucket.AllowDirectoryListing),
		svc1log.SafeParam("allowAnonymousRead", externalBucket.AllowAnonymousRead),
		svc1log.SafeParam("errorCount", len(errors)))

	return &report, errors
}

// ExternalEnumerateS3 attempts to enumerate a public facing S3 bucket with no credentials
func ExternalEnumerateS3(ctx context.Context, config s3fern.S3ExternalConfig) s3fern.ExternalS3Report {
	log := svc1log.FromContext(ctx)
	log.Info("Starting external S3 enumeration", svc1log.SafeParam("bucketURL", config.BucketUrl))

	report := s3fern.ExternalS3Report{Config: &config}
	result := s3fern.ExternalS3BucketResult{}
	errors := []string{}

	// Parse the bucket URL to get name and potentially region
	bucketName, urlRegion := parseBucketURL(config.BucketUrl)

	// If we got a region from the URL, only check that region
	regionsToCheck := config.Regions
	if urlRegion != "" {
		regionsToCheck = []string{urlRegion}
	}

	// For non-standard URLs, try the default region first
	if isNonStandardS3URL(config.BucketUrl) {
		regionsToCheck = append([]string{"us-east-1"}, regionsToCheck...)
	}

	bucketFound := false
	for _, region := range regionsToCheck {
		exists, err := bucketExists(ctx, region, bucketName)
		if err != nil {
			log.Warn("Error checking bucket in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error checking bucket in region %s: %v", region, err))
			continue
		}
		if exists {
			log.Info("Found bucket in region",
				svc1log.SafeParam("bucketName", bucketName),
				svc1log.SafeParam("region", region))
			functionResult, functionErrors := externalEnumerateS3Region(ctx, config.BucketUrl, bucketName, region)
			if functionResult != nil {
				result = *functionResult
			}
			errors = append(errors, functionErrors...)
			bucketFound = true
			break
		}
	}

	if !bucketFound {
		log.Warn("Bucket not found in any specified regions",
			svc1log.SafeParam("bucketName", bucketName),
			svc1log.SafeParam("regionsChecked", len(regionsToCheck)))
		errors = append(errors, "Bucket not found in any of the specified regions")
	}

	report.Result = &result
	report.Errors = errors

	log.Info("External S3 enumeration completed",
		svc1log.SafeParam("bucketFound", bucketFound),
		svc1log.SafeParam("totalErrors", len(errors)))

	return report
}
