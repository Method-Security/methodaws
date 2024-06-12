package sts

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func GetAccountID(ctx context.Context, cfg aws.Config) (*string, error) {
	client := sts.NewFromConfig(cfg)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	return result.Account, nil
}

func GetCallerArn(ctx context.Context, cfg aws.Config) (*string, error) {
	client := sts.NewFromConfig(cfg)
	result, err := client.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, err
	}
	return result.Arn, nil
}
