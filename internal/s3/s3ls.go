package s3

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type BucketObject struct {
	Name string `json:"name" yaml:"name"`
	Size int64  `json:"size" yaml:"size"`
}

type LsResources struct {
	S3BucketName  *string        `json:"name" yaml:"name"`
	BucketObjects []BucketObject `json:"objects" yaml:"objects"`
}

type LsResourceReport struct {
	Resources LsResources `json:"resources" yaml:"resources"`
	Errors    []string    `json:"errors" yaml:"errors"`
}

func LsS3Bucket(ctx context.Context, cfg aws.Config, bucketName string) (*LsResourceReport, error) {
	s3Client := s3.NewFromConfig(cfg)
	errors := []string{}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(bucketName),
	}

	var bucketObjects []BucketObject

	paginator := s3.NewListObjectsV2Paginator(s3Client, input)
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.Background())
		if err != nil {
			errors = append(errors, err.Error())
		}
		for _, item := range output.Contents {
			bucketObjects = append(bucketObjects, BucketObject{
				Name: *item.Key,
				Size: *item.Size,
			})
		}
	}

	resources := LsResources{
		S3BucketName:  aws.String(bucketName),
		BucketObjects: bucketObjects,
	}

	report := LsResourceReport{
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}
