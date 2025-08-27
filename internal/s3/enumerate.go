// Package s3 provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package s3

import (
	// Standard
	"context"
	"fmt"

	// Generated
	s3fern "github.com/Method-Security/methodaws/generated/go/s3"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func publicAccess(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	input := &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetPublicAccessBlock(ctx, input)
	if err != nil {
		log.Warn("Failed to get public access block configuration",
			svc1log.SafeParam("bucketName", bucket.Name),
			svc1log.Stacktrace(err))
		return bucket, err
	}

	bucket.PublicAccessConfig = &s3fern.S3PublicAccessBlockConfiguration{
		BlockPublicAcls:       *result.PublicAccessBlockConfiguration.BlockPublicAcls,
		IgnorePublicAcls:      *result.PublicAccessBlockConfiguration.IgnorePublicAcls,
		BlockPublicPolicy:     *result.PublicAccessBlockConfiguration.BlockPublicPolicy,
		RestrictPublicBuckets: *result.PublicAccessBlockConfiguration.RestrictPublicBuckets,
	}

	return bucket, nil
}

func bucketEncryption(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	input := &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketEncryption(ctx, input)

	if err != nil {
		log.Warn("Failed to get bucket encryption configuration",
			svc1log.SafeParam("bucketName", bucket.Name),
			svc1log.Stacktrace(err))
		return bucket, err
	}

	if result.ServerSideEncryptionConfiguration != nil {
		encryptionRules := []*s3fern.EncryptionRule{}
		for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
			encryptionRule := s3fern.EncryptionRule{}
			sseAlgorithm, _ := s3fern.NewS3ServerSideEncryptionFromString(string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm))
			encryptionRule.SseAlgorithm = &sseAlgorithm
			encryptionRule.KmsMasterKeyId = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
			encryptionRules = append(encryptionRules, &encryptionRule)
		}
		bucket.EncryptionRules = encryptionRules
	}
	return bucket, nil
}

func objectVersioning(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	input := &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketVersioning(ctx, input)
	if err != nil {
		log.Warn("Failed to get bucket versioning configuration",
			svc1log.SafeParam("bucketName", bucket.Name),
			svc1log.Stacktrace(err))
		return bucket, err
	}

	bucketVersioning, _ := s3fern.NewBucketVersioningStatusFromString(string(result.Status))
	bucket.BucketVersioning = &bucketVersioning
	mfaDelete, _ := s3fern.NewS3MfaDeleteStatusFromString(string(result.MFADelete))
	bucket.MfaDelete = &mfaDelete

	return bucket, nil
}

func bucketPolicy(ctx context.Context, s3Client *s3.Client, bucket *s3fern.S3Bucket) (*s3fern.S3Bucket, error) {
	log := svc1log.FromContext(ctx)

	input := s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketPolicy(ctx, &input)
	if err != nil {
		log.Warn("Failed to get bucket policy",
			svc1log.SafeParam("bucketName", bucket.Name),
			svc1log.Stacktrace(err))
		return bucket, err
	}

	bucket.Policy = result.Policy

	return bucket, nil
}

// EnumerateS3 retrieves all S3 buckets available to the caller and returns an EnumerateResourceReport struct. Non-fatal
// errors that occur during the execution of the `methodaws s3 enumerate` subcommand are included in the report, but
// the function will not return an error unless there is an issue retrieving the account ID.

func EnumerateS3(ctx context.Context, awscfg aws.Config, config s3fern.S3EnumerateConfig) *s3fern.S3EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting S3 enumeration", svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Initialize report
	report := &s3fern.S3EnumerateReport{
		Config: &config,
		Result: &s3fern.S3EnumerateResult{},
	}
	errors := []string{}

	// Use a single region to list all buckets (buckets are globally shared)
	// S3 bucket location constraints explained:
	//
	// 1. Empty LocationConstraint:
	//    - Indicates the bucket is in the US East (N. Virginia) region (us-east-1).
	//    - Example: &{LocationConstraint: ResultMetadata:{...}}
	//    - This is due to historical reasons:
	//      a) When S3 was first launched, it was only available in us-east-1.
	//      b) To maintain backwards compatibility, buckets in this region have an empty location constraint.
	//
	// 2. Non-empty LocationConstraint:
	//    - Directly corresponds to the region code where the bucket is located.
	//    - Example: &{LocationConstraint:us-west-1 ResultMetadata:{...}}
	//
	// The region field in the final signal output will always explicitly state the correct region,
	// regardless of whether the LocationConstraint is empty or not.
	client := s3.NewFromConfig(awscfg)

	log.Info("Listing S3 buckets", svc1log.SafeParam("accountId", aws.ToString(&config.AccountId)))
	listBucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		log.Error("Failed to list S3 buckets", svc1log.Stacktrace(err))
		errors = append(errors, err.Error())
		report.Errors = errors
		return report
	}

	// Create a map of buckets by region for efficient processing
	bucketsByRegion := make(map[string][]s3fern.S3Bucket)
	errorMessages := []string{}

	// First pass: get all bucket regions and group them
	for _, bucket := range listBucketsOutput.Buckets {
		s3Bucket := s3fern.S3Bucket{
			CreationDate: aws.ToTime(bucket.CreationDate),
			Name:         aws.ToString(bucket.Name),
			OwnerId:      aws.ToString(listBucketsOutput.Owner.ID),
			OwnerName:    aws.ToString(listBucketsOutput.Owner.DisplayName),
		}

		// Get the bucket's region
		regionOutput, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			log.Warn("Failed to get bucket region",
				svc1log.SafeParam("bucketName", *bucket.Name),
				svc1log.Stacktrace(err))
			errorMessages = append(errorMessages, fmt.Sprintf("Error getting location for bucket %s: %v", *bucket.Name, err))
			continue
		}

		// If the region is empty, set it to us-east-1
		s3Bucket.Region = string(regionOutput.LocationConstraint)
		if s3Bucket.Region == "" {
			s3Bucket.Region = "us-east-1"
		}

		// Group buckets by region
		bucketsByRegion[s3Bucket.Region] = append(bucketsByRegion[s3Bucket.Region], s3Bucket)
	}

	s3Buckets := []*s3fern.S3Bucket{}

	// Determine which regions to process
	regionsToProcess := config.Regions
	if len(config.Regions) == 0 {
		// If no regions specified, process all regions found
		regionsToProcess = make([]string, 0, len(bucketsByRegion))
		for region := range bucketsByRegion {
			regionsToProcess = append(regionsToProcess, region)
		}
	}

	// Process buckets for each region
	for _, region := range regionsToProcess {
		bucketsInRegion, exists := bucketsByRegion[region]
		if !exists {
			log.Debug("No buckets found in region", svc1log.SafeParam("region", region))
			continue
		}

		log.Info("Processing S3 buckets in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("bucketCount", len(bucketsInRegion)))

		// Create a new AWS config for this region
		regionCfg := awscfg.Copy()
		regionCfg.Region = region
		regionClient := s3.NewFromConfig(regionCfg)

		// Process each bucket in this region
		for _, s3Bucket := range bucketsInRegion {
			bucketPtr := &s3Bucket

			// Fetch additional bucket details
			bucketPtr, err = bucketPolicy(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			bucketPtr, err = objectVersioning(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			bucketPtr, err = bucketEncryption(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			bucketPtr, err = publicAccess(ctx, regionClient, bucketPtr)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
			}

			bucketPtr.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketPtr.Name, bucketPtr.Region)

			bucketARN := arn.ARN{
				Partition: "aws",
				Service:   "s3",
				Resource:  bucketPtr.Name,
			}
			bucketPtr.Arn = bucketARN.String()

			s3Buckets = append(s3Buckets, bucketPtr)
		}
	}
	if len(s3Buckets) > 0 {
		report.Result.S3Buckets = s3Buckets
	}
	report.Errors = errorMessages
	return report
}
