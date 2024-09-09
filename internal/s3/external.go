package s3

import (
	"context"
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go/aws/awserr"
)

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

// listBucketContents lists all objects in a bucket
func listBucketContents(ctx context.Context, client *s3.Client, bucketName string) ([]*methodaws.S3ObjectDetails, error) {
	directoryContents := []*methodaws.S3ObjectDetails{}
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	// Capture all objects in the bucket
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("error listing bucket contents: %v", err)
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

	return directoryContents, nil
}

// checkListingAllowed checks if listing objects is allowed on a bucket
func checkListingAllowed(ctx context.Context, client *s3.Client, bucketName string) bool {
	maxKeys := int32(1)
	_, err := client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		MaxKeys: &maxKeys,
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

// checkAcl checks the bucket ACL
func checkACL(ctx context.Context, client *s3.Client, bucketName string) ([]*methodaws.S3BucketAcl, error) {
	aclOutput, err := client.GetBucketAcl(ctx, &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err != nil {
		return nil, fmt.Errorf("error getting bucket ACL: %v", err)
	}

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

	return acls, nil
}

// externalEnumerateS3Region enumerates a single public facing S3 bucket in a specific region.
// If the bucket does not exist, it will return an unmodified report (with potential new errors).
func ExternalEnumerateS3Region(ctx context.Context, report methodaws.ExternalS3Report, bucketName string, region string) methodaws.ExternalS3Report {
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
	externalBucket.Name = bucketName
	externalBucket.Url = fmt.Sprintf("https://%s.s3.%s.amazonaws.com", bucketName, cfg.Region)
	externalBucket.Region = region

	// List bucket contents
	directoryContents, err := listBucketContents(ctx, client, bucketName)
	if err != nil {
		report.Errors = append(report.Errors, fmt.Sprintf("error listing bucket contents: %v", err))
	} else {
		externalBucket.DirectoryContents = directoryContents
	}

	// Check if listing is allowed
	externalBucket.AllowDirectoryListing = checkListingAllowed(ctx, client, bucketName)

	// Check if anonymous read is allowed using the first object key, if available
	externalBucket.AllowAnonymousRead = checkAnonymousReadAllowed(ctx, client, bucketName, directoryContents)

	// Check bucket policy
	policy, err := checkPolicy(ctx, client, bucketName)
	if err == nil {
		externalBucket.Policy = &policy
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("Error getting bucket policy: %v", err))
	}

	// Check bucket ACL
	acls, err := checkACL(ctx, client, bucketName)
	if err == nil {
		externalBucket.Acls = acls
	} else {
		report.Errors = append(report.Errors, fmt.Sprintf("Error getting bucket ACL: %v", err))
	}

	report.ExternalBuckets = append(report.ExternalBuckets, &externalBucket)
	return report
}

// ExternalEnumerateS3 attempts to enumerate a public facing S3 bucket with no credentials.
// If the bucket does not exist, it will return an empty report.
func ExternalEnumerateS3(ctx context.Context, cfg aws.Config, bucketName string, regions []string) methodaws.ExternalS3Report {
	report := methodaws.ExternalS3Report{
		ExternalBuckets: []*methodaws.ExternalBucket{},
		Errors:          []string{},
	}

	for _, region := range regions {
		r := ExternalEnumerateS3Region(ctx, report, bucketName, region)
		report.Errors = append(report.Errors, r.Errors...)
		report.ExternalBuckets = append(report.ExternalBuckets, r.ExternalBuckets...)
	}

	return report
}
