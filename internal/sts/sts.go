// Package sts provides the data structures and logic necessary to interact with the AWS Security Token Service (STS).
package sts

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// GetAccountID retrieves the account ID of the credentials that are being leveraged in this session. It provides
// an easy way to determine the account ID of the caller which is used throughout methodaws to enrich various
// resources with the account ID.
func GetAccountID(ctx context.Context, cfg aws.Config) (*string, error) {
	client := sts.NewFromConfig(cfg)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	return result.Account, nil
}

// GetCallerArn retrieves the ARN of the credentials that are being leveraged in this session. It provides
// an easy way to determine the ARN of the caller which is used throughout methodaws to enrich various
// resources.
func GetCallerArn(ctx context.Context, cfg aws.Config) (*string, error) {
	client := sts.NewFromConfig(cfg)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	return result.Arn, nil
}
