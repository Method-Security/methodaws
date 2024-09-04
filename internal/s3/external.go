package s3

import (
	"context"
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

func getAWSRegions() []string {
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()

	var regions []string
	for _, p := range partitions {
		for region := range p.Regions() {
			regions = append(regions, region)
		}
	}

	return regions
}

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

	// Call HeadBucket operation
	_, err = client.HeadBucket(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(bucketName),
	})

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case "NotFound":
				return false, nil
			case "Forbidden":
				return true, nil
			default:
				return false, fmt.Errorf("error checking bucket: %v", err)
			}
		}
		return false, fmt.Errorf("error checking bucket: %v", err)
	}

	// If there's no error, the bucket exists
	return true, nil
}

// externalEnumerateS3Region enumerates a single public facing S3 bucket in a specific region.
// If the bucket does not exist, it will return an unmodified report (with potential new errors).
func externalEnumerateS3Region(ctx context.Context, report methodaws.ExternalS3Report, bucketName string, region string) methodaws.ExternalS3Report {
	// Check if bucket exists before proceeding
	exists, err := bucketExists(ctx, region, bucketName)
	if err != nil {
		return report
	}
	if !exists {
		return report
	}

	// Enumerate the bucket
	externalBucket := methodaws.ExternalBucket{}

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

	// Populate basic information
	externalBucket.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, cfg.Region)
	externalBucket.Region = region

	// List bucket contents
	directoryContents := []*methodaws.S3ObjectDetails{}
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	// Capture all objects in the bucket
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("error listing bucket contents: %v", err))
			break
		}

		for _, object := range page.Contents {
			var size int
			if object.Size != nil {
				size = int(*object.Size)
			}
			var ownerID string
			var ownerName string
			if object.Owner != nil {
				ownerID = *object.Owner.ID
				ownerName = *object.Owner.DisplayName
			}
			directoryContents = append(directoryContents, &methodaws.S3ObjectDetails{
				Key:          *object.Key,
				LastModified: object.LastModified,
				Size:         &size,
				OwnerId:      &ownerID,
				OwnerName:    &ownerName,
			})
		}
	}
	externalBucket.DirectoryContents = directoryContents

	// Check if listing is allowed
	maxKeys := int32(1)
	_, err = client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		MaxKeys: &maxKeys,
	})
	externalBucket.AllowDirectoryListing = (err == nil)

	// Check if anonymous read is allowed using the first object key, if available
	if len(directoryContents) > 0 {
		_, err = client.GetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(directoryContents[0].Key),
		})
		externalBucket.AllowAnonymousRead = (err == nil)
	} else {
		externalBucket.AllowAnonymousRead = false
	}

	// Check bucket policy
	policyOutput, err := client.GetBucketPolicy(ctx, &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil && policyOutput.Policy != nil {
		externalBucket.Policy = policyOutput.Policy
	}

	// Check bucket ACL
	aclOutput, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		acls := []*methodaws.S3BucketAcl{}
		for _, grant := range aclOutput.Grants {
			if grant.Grantee.URI != nil {
				acl := &methodaws.S3BucketAcl{
					GranteeUri: *grant.Grantee.URI,
					Permission: string(grant.Permission),
				}
				acls = append(acls, acl)
			}
		}
		externalBucket.Acls = acls
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("Error getting bucket ACL: %v", err))
	}

	report.ExternalBuckets = append(report.ExternalBuckets, &externalBucket)
	return report
}

// ExternalEnumerateS3 attempts to enumerate a public facing S3 bucket with no credentials.
// If the bucket does not exist, it will return an empty report.
// If region is "all", it will attempt to enumerate the bucket in all regions.
func ExternalEnumerateS3(ctx context.Context, cfg aws.Config, bucketName string) methodaws.ExternalS3Report {
	report := methodaws.ExternalS3Report{
		ExternalBuckets: []*methodaws.ExternalBucket{},
		Errors:          []string{},
	}

	// If region is not "all", use specified region, otherwise attempt all regions
	if cfg.Region != "all" {
		report = externalEnumerateS3Region(ctx, report, bucketName, cfg.Region)
	} else {
		for _, region := range getAWSRegions() {
			report = externalEnumerateS3Region(ctx, report, bucketName, region)
		}
	}

	return report
}
