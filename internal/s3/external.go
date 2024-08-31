package s3

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	methodaws "github.com/Method-Security/methodaws/generated/go"
)

// TODO proper docs
func ExternalEnumerateS3(ctx context.Context, bucketURL string) methodaws.ExternalS3Report {
	// Parse the URL to extract bucket name and region

	parsedURL, err := url.Parse(bucketURL)
	if err != nil {
		fmt.Printf("error parsing URL: %v", err)
		return methodaws.ExternalS3Report{}
	}

	bucketName := strings.Split(parsedURL.Hostname(), ".")[0]
	region := "us-east-1" // Default to us-east-1, adjust if needed

	// Create a custom AWS config with anonymous credentials
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(region),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("", "", "")),
	)
	if err != nil {
		fmt.Printf("error loading AWS config: %v", err)
		return methodaws.ExternalS3Report{}
	}

	// Create an S3 client
	client := s3.NewFromConfig(cfg)

	// List bucket contents
	fmt.Println("Bucket Contents:")
	paginator := s3.NewListObjectsV2Paginator(client, &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			fmt.Printf("error listing bucket contents: %v", err)
			return methodaws.ExternalS3Report{}
		}

		for _, object := range page.Contents {
			fmt.Printf("- %s (Size: %d, Last Modified: %s)\n", *object.Key, object.Size, object.LastModified)
		}
	}

	// Check permissions and settings
	fmt.Println("\nPermissions and Settings:")

	// Check if listing is allowed
	maxKeys := int32(1)
	_, err = client.ListObjectsV2(context.TODO(), &s3.ListObjectsV2Input{
		Bucket:  aws.String(bucketName),
		MaxKeys: &maxKeys,
	})
	fmt.Printf("Directory Listing: %v\n", err == nil)

	// Check if anonymous read is allowed
	_, err = client.GetObject(context.TODO(), &s3.GetObjectInput{
		Bucket: aws.String(bucketName),
		Key:    aws.String("test-object"),
	})
	fmt.Printf("Anonymous Read: %v\n", err == nil)

	// Check for website configuration
	_, err = client.GetBucketWebsite(context.TODO(), &s3.GetBucketWebsiteInput{
		Bucket: aws.String(bucketName),
	})
	fmt.Printf("Website Enabled: %v\n", err == nil)

	// Check bucket policy
	_, err = client.GetBucketPolicy(context.TODO(), &s3.GetBucketPolicyInput{
		Bucket: aws.String(bucketName),
	})
	fmt.Printf("Has Bucket Policy: %v\n", err == nil)

	// Check bucket ACL
	aclOutput, err := client.GetBucketAcl(context.TODO(), &s3.GetBucketAclInput{
		Bucket: aws.String(bucketName),
	})
	if err == nil {
		fmt.Println("Bucket ACL:")
		for _, grant := range aclOutput.Grants {
			fmt.Printf("- Grantee: %s, Permission: %s\n", *grant.Grantee.URI, grant.Permission)
		}
	}

	return methodaws.ExternalS3Report{}
}