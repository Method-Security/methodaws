// Package utils provides common utility functions used across the methodaws codebase.
package utils

import (
	"fmt"
)

// BuildARN constructs an AWS ARN (Amazon Resource Name) with the standard format:
// arn:aws:service:region:account-id:resource-type/resource-id
func BuildARN(service, region, accountID, resourceType, resourceID string) string {
	return fmt.Sprintf("arn:aws:%s:%s:%s:%s/%s", service, region, accountID, resourceType, resourceID)
}
