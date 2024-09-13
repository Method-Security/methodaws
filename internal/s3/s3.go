// Package s3 provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package s3

import (
	"context"
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func publicAccess(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
	input := &s3.GetPublicAccessBlockInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetPublicAccessBlock(ctx, input)
	if err != nil {
		return bucket, err
	}

	bucket.PublicAccessConfig = &methodaws.S3PublicAccessBlockConfiguration{
		BlockPublicAcls:       *result.PublicAccessBlockConfiguration.BlockPublicAcls,
		IgnorePublicAcls:      *result.PublicAccessBlockConfiguration.IgnorePublicAcls,
		BlockPublicPolicy:     *result.PublicAccessBlockConfiguration.BlockPublicPolicy,
		RestrictPublicBuckets: *result.PublicAccessBlockConfiguration.RestrictPublicBuckets,
	}

	return bucket, nil
}

func bucketEncryption(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
	input := &s3.GetBucketEncryptionInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketEncryption(ctx, input)

	if err != nil {
		return bucket, err
	}

	if result.ServerSideEncryptionConfiguration != nil {
		encryptionRules := []*methodaws.EncryptionRule{}
		for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
			encryptionRule := methodaws.EncryptionRule{}
			sseAlgorithm, _ := methodaws.NewS3ServerSideEncryptionFromString(string(rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm))
			encryptionRule.SseAlgorithm = &sseAlgorithm
			encryptionRule.KmsMasterKeyId = rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID
			encryptionRules = append(encryptionRules, &encryptionRule)
		}
		bucket.EncryptionRules = encryptionRules
	}
	return bucket, nil
}

func objectVersioning(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
	input := &s3.GetBucketVersioningInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketVersioning(ctx, input)
	if err != nil {
		return bucket, err
	}

	bucketVersioning, _ := methodaws.NewBucketVersioningStatusFromString(string(result.Status))
	bucket.BucketVersioning = &bucketVersioning
	mfaDelete, _ := methodaws.NewS3MfaDeleteStatusFromString(string(result.MFADelete))
	bucket.MfaDelete = &mfaDelete

	return bucket, nil
}

func bucketPolicy(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
	input := s3.GetBucketPolicyInput{
		Bucket: aws.String(bucket.Name),
	}

	result, err := s3Client.GetBucketPolicy(ctx, &input)
	if err != nil {
		return bucket, err
	}

	bucket.Policy = result.Policy

	return bucket, nil
}

// EnumerateS3 retrieves all S3 buckets available to the caller and returns an EnumerateResourceReport struct. Non-fatal
// errors that occur during the execution of the `methodaws s3 enumerate` subcommand are included in the report, but
// the function will not return an error unless there is an issue retrieving the account ID.

func EnumerateS3(ctx context.Context, cfg aws.Config, regions []string) methodaws.S3Report {
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return methodaws.S3Report{
			AccountId: aws.ToString(accountID),
			S3Buckets: []*methodaws.Bucket{},
			Errors:    []string{err.Error()},
		}
	}

	// Use a single region to list all buckets (buckets are globally shared)
	cfg.Region = "us-east-1"
	client := s3.NewFromConfig(cfg)

	listBucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return methodaws.S3Report{
			AccountId: aws.ToString(accountID),
			S3Buckets: []*methodaws.Bucket{},
			Errors:    []string{err.Error()},
		}
	}

	s3Buckets := []*methodaws.Bucket{}
	errorMessages := []string{}

	for _, bucket := range listBucketsOutput.Buckets {
		s3Bucket := &methodaws.Bucket{
			CreationDate: aws.ToTime(bucket.CreationDate),
			Name:         aws.ToString(bucket.Name),
			OwnerId:      aws.ToString(listBucketsOutput.Owner.ID),
			OwnerName:    aws.ToString(listBucketsOutput.Owner.DisplayName),
		}

		// Get the bucket's region
		regionOutput, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name})
		if err != nil {
			errorMessages = append(errorMessages, fmt.Sprintf("Error getting location for bucket %s: %v", *bucket.Name, err))
			continue
		}
		s3Bucket.Region = string(regionOutput.LocationConstraint)
		if s3Bucket.Region == "" {
			s3Bucket.Region = "us-east-1" // Default region if empty
		}

		// Create a new client for the bucket's specific region
		bucketCfg := cfg.Copy()
		bucketCfg.Region = s3Bucket.Region
		bucketClient := s3.NewFromConfig(bucketCfg)

		// Fetch additional bucket details
		s3Bucket, err = bucketPolicy(ctx, bucketClient, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = objectVersioning(ctx, bucketClient, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = bucketEncryption(ctx, bucketClient, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = publicAccess(ctx, bucketClient, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", *bucket.Name, s3Bucket.Region)

		bucketARN := arn.ARN{
			Partition: "aws",
			Service:   "s3",
			Resource:  *bucket.Name,
		}
		s3Bucket.Arn = bucketARN.String()

		s3Buckets = append(s3Buckets, s3Bucket)
	}

	return methodaws.S3Report{
		AccountId: aws.ToString(accountID),
		S3Buckets: s3Buckets,
		Errors:    errorMessages,
	}
}
