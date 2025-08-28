// Package utils provides common utility functions used across the methodaws codebase.
package utils

import (
	"context"
	"fmt"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// GetAccountID retrieves the account ID for the given AWS configuration.
// It returns the account ID as a string and an error if the account ID cannot be retrieved.
func GetAccountID(ctx context.Context, awsConfig aws.Config) (string, error) {
	accountID, err := sts.GetAccountID(ctx, awsConfig)
	if err != nil {
		return "", fmt.Errorf("failed to get account ID: %w", err)
	}

	if accountID == nil {
		return "", fmt.Errorf("account ID is nil")
	}

	return aws.ToString(accountID), nil
}
