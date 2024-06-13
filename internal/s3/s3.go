package s3

import (
	"context"
	"time"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

type EncryptionRule struct {
	SSEAlgorithm   types.ServerSideEncryption `json:"sse_algorithm" yaml:"sse_algorithm"`
	KMSMasterKeyID *string                    `json:"kms_master_key_id" yaml:"kms_master_key_id"`
}

type Bucket struct {
	CreationDate       *time.Time                           `json:"creation_date" yaml:"creation_date"`
	Name               *string                              `json:"name" yaml:"name"`
	Owner              types.Owner                          `json:"owner" yaml:"owner"`
	Policy             *string                              `json:"policy" yaml:"policy"`
	BucketVersioning   types.BucketVersioningStatus         `json:"bucket_versioning" yaml:"bucket_versioning"`
	MFADelete          types.MFADeleteStatus                `json:"mfa_delete" yaml:"mfa_delete"`
	EncryptionRules    []EncryptionRule                     `json:"encryption_rules" yaml:"encryption_rules"`
	PublicAccessConfig types.PublicAccessBlockConfiguration `json:"public_access_config" yaml:"public_access_config"`
}

type EnumerateResources struct {
	S3Buckets []Bucket `json:"s3_buckets" yaml:"s3_buckets"`
}

type EnumerateResourceReport struct {
	AccountID string             `json:"account_id" yaml:"account_id"`
	Resources EnumerateResources `json:"resources" yaml:"resources"`
	Errors    []string           `json:"errors" yaml:"errors"`
}

func publicAccess(ctx context.Context, s3Client *s3.Client, bucket *Bucket) (*Bucket, error) {
	input := &s3.GetPublicAccessBlockInput{
		Bucket: bucket.Name,
	}

	result, err := s3Client.GetPublicAccessBlock(ctx, input)
	if err != nil {
		return bucket, err
	}

	bucket.PublicAccessConfig = *result.PublicAccessBlockConfiguration
	return bucket, nil
}

func bucketEncryption(ctx context.Context, s3Client *s3.Client, bucket *Bucket) (*Bucket, error) {
	input := &s3.GetBucketEncryptionInput{
		Bucket: aws.String(*bucket.Name),
	}

	result, err := s3Client.GetBucketEncryption(ctx, input)

	if err != nil {
		return bucket, err
	}

	if result.ServerSideEncryptionConfiguration != nil {
		var encryptionRules []EncryptionRule
		for _, rule := range result.ServerSideEncryptionConfiguration.Rules {
			encryptionRules = append(encryptionRules, EncryptionRule{
				SSEAlgorithm:   rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm,
				KMSMasterKeyID: rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID,
			})
		}
		bucket.EncryptionRules = encryptionRules
	}
	return bucket, nil
}

func objectVersioning(ctx context.Context, s3Client *s3.Client, bucket *Bucket) (*Bucket, error) {
	input := &s3.GetBucketVersioningInput{
		Bucket: aws.String(*bucket.Name),
	}

	result, err := s3Client.GetBucketVersioning(ctx, input)
	if err != nil {
		return bucket, err
	}

	bucket.BucketVersioning = result.Status
	bucket.MFADelete = result.MFADelete
	return bucket, nil
}

func bucketPolicy(ctx context.Context, s3Client *s3.Client, bucket *Bucket) (*Bucket, error) {
	input := s3.GetBucketPolicyInput{
		Bucket: aws.String(*bucket.Name),
	}

	result, err := s3Client.GetBucketPolicy(ctx, &input)
	if err != nil {
		return bucket, err
	}

	bucket.Policy = result.Policy
	return bucket, nil
}

func EnumerateS3(ctx context.Context, cfg aws.Config) (*EnumerateResourceReport, error) {
	s3Client := s3.NewFromConfig(cfg)
	resources := EnumerateResources{}
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &EnumerateResourceReport{Errors: errors}, err
	}

	listBucketsOutput, err := s3Client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for _, bucket := range listBucketsOutput.Buckets {
			s3Bucket := &Bucket{
				CreationDate: bucket.CreationDate,
				Name:         bucket.Name,
				Owner:        *listBucketsOutput.Owner,
			}

			s3Bucket, err = bucketPolicy(ctx, s3Client, s3Bucket)
			if err != nil {
				errors = append(errors, err.Error())
			}

			s3Bucket, err = objectVersioning(ctx, s3Client, s3Bucket)
			if err != nil {
				errors = append(errors, err.Error())
			}

			s3Bucket, err = bucketEncryption(ctx, s3Client, s3Bucket)
			if err != nil {
				errors = append(errors, err.Error())
			}

			s3Bucket, err = publicAccess(ctx, s3Client, s3Bucket)
			if err != nil {
				errors = append(errors, err.Error())
			}

			resources.S3Buckets = append(resources.S3Buckets, *s3Bucket)
		}
	}

	report := EnumerateResourceReport{
		AccountID: *accountID,
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}
