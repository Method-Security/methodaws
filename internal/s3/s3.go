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

// EnumerateS3ForRegion retrieves all S3 buckets available to the caller and returns an EnumerateResourceReport struct. Non-fatal
// errors that occur during the execution of the `methodaws s3 enumerate` subcommand are included in the report, but
// the function will not return an error unless there is an issue retrieving the account ID.
func EnumerateS3ForRegion(ctx context.Context, cfg aws.Config, region string) methodaws.S3Report {
	cfg.Region = region

	client := s3.NewFromConfig(cfg)

	s3Buckets := []*methodaws.Bucket{}
	errorMessages := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.S3Report{
			AccountId: aws.ToString(accountID),
			S3Buckets: s3Buckets,
			Errors:    errorMessages,
		}
	}

	listBucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.S3Report{
			AccountId: aws.ToString(accountID),
			S3Buckets: s3Buckets,
			Errors:    errorMessages,
		}
	}

	for _, bucket := range listBucketsOutput.Buckets {
		s3Bucket := &methodaws.Bucket{
			CreationDate: aws.ToTime(bucket.CreationDate),
			Name:         aws.ToString(bucket.Name),
			OwnerId:      aws.ToString(listBucketsOutput.Owner.ID),
			OwnerName:    aws.ToString(listBucketsOutput.Owner.DisplayName),
			Region:       region,
		}

		s3Bucket, err = bucketPolicy(ctx, client, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = objectVersioning(ctx, client, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = bucketEncryption(ctx, client, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		s3Bucket, err = publicAccess(ctx, client, s3Bucket)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
		}

		// Use virtual host style URL; path based is still valid but less common
		s3Bucket.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", *bucket.Name, cfg.Region)

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

func EnumerateS3(ctx context.Context, cfg aws.Config, regions []string) methodaws.S3Report {
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return methodaws.S3Report{
			AccountId: aws.ToString(accountID),
			S3Buckets: []*methodaws.Bucket{},
			Errors:    []string{err.Error()},
		}
	}

	report := methodaws.S3Report{
		AccountId: aws.ToString(accountID),
		S3Buckets: []*methodaws.Bucket{},
		Errors:    []string{},
	}

	for _, region := range regions {
		r := EnumerateS3ForRegion(ctx, cfg, region)
		if r.Errors != nil {
			report.Errors = append(report.Errors, r.Errors...)
		}
		report.S3Buckets = append(report.S3Buckets, r.S3Buckets...)
	}

	return report
}
