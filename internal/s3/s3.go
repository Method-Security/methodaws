// Package s3 provides the data structures and logic necessary to enumerate and integrate AWS S3 resources.
package s3

import (
	"context"
	"time"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	methodaws "github.com/Method-Security/methodaws/generated/go"
)

// EncryptionRule contains the server-side encryption configuration for an S3 bucket alongside the KMS master key ID
// used for encryption (if it exists).
type EncryptionRule struct {
	SSEAlgorithm   types.ServerSideEncryption `json:"sse_algorithm" yaml:"sse_algorithm"`
	KMSMasterKeyID *string                    `json:"kms_master_key_id" yaml:"kms_master_key_id"`
}

// Bucket contains the metadata for an S3 bucket, including its creation date, name, owner, policy,
// bucket versioning status, etc. This data typically requires multiple API calls to retrieve, so collecting
// it all in one struct is useful for reporting purposes.
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

// EnumerateResources contains the S3 buckets that were enumerated.
type EnumerateResources struct {
	S3Buckets []Bucket `json:"s3_buckets" yaml:"s3_buckets"`
}

// EnumerateResourceReport contains the account ID that the S3 buckets were discovered in, the resources themselves,
// and any non-fatal errors that occurred during the execution of the `methodaws s3 enumerate` subcommand.
type EnumerateResourceReport struct {
	AccountID string             `json:"account_id" yaml:"account_id"`
	Resources EnumerateResources `json:"resources" yaml:"resources"`
	Errors    []string           `json:"errors" yaml:"errors"`
}

func publicAccess(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
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

func bucketEncryption(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
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

func objectVersioning(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
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

func bucketPolicy(ctx context.Context, s3Client *s3.Client, bucket *methodaws.Bucket) (*methodaws.Bucket, error) {
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

// EnumerateS3 retrieves all S3 buckets available to the caller and returns an EnumerateResourceReport struct. Non-fatal
// errors that occur during the execution of the `methodaws s3 enumerate` subcommand are included in the report, but
// the function will not return an error unless there is an issue retrieving the account ID.
func EnumerateS3(ctx context.Context, cfg aws.Config) methodaws.S3Report {
	client := s3.NewFromConfig(cfg)

	s3Buckets := []*methodaws.Bucket{}
	errorMessages := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.S3Report{
			AccountId:  aws.ToString(accountID),
			S3Buckets: 	s3Buckets,
			Errors:    	errorMessages,
		}
	}

	listBucketsOutput, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.S3Report{
			AccountId:  aws.ToString(accountID),
			S3Buckets: 	s3Buckets,
			Errors:    	errorMessages,
		}
	} else {
		for _, bucket := range listBucketsOutput.Buckets {
			s3Bucket := &methodaws.Bucket{
				CreationDate: aws.ToTime(bucket.CreationDate),
				Name:         aws.ToString(bucket.Name),
				OwnerId:      aws.ToString(listBucketsOutput.Owner.ID),
				OwnerName:	  aws.ToString(listBucketsOutput.Owner.DisplayName),
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

			s3Buckets = append(s3Buckets, s3Bucket)
		}
	}

	return methodaws.S3Report{
		AccountId:  aws.ToString(accountID),
		S3Buckets: 	s3Buckets,
		Errors:    	errorMessages,
	}
}
