// Package current contains all logic and data structures relevant to the current state of the AWS instance. It is
// primarily leveraged by the `methodaws current` subcommand.
package current

import (
	"context"
	"errors"
	"fmt"
	"strings"

	identity "github.com/Method-Security/methodaws/internal/iam"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// IamResourceReport represents the output of the `methodaws current iam` subcommand. It contains the inline policies,
// attached policies, and role details of the current IAM role. It also contains any errors that occurred during the
// execution of the subcommand.
type IamResourceReport struct {
	InlinePolicies   []*iam.GetRolePolicyOutput `json:"inlinePolicies" yaml:"inlinePolicies"`
	AttachedPolicies []identity.PolicyResource  `json:"attachedPolicies" yaml:"attachedPolicies"`
	Role             *types.Role                `json:"role" yaml:"role"`
	Errors           []string                   `json:"errors" yaml:"errors"`
}

// IamDetails is responsible for gathering the IAM role details, inline policies, and attached policies for any IAM
// roles that are associated with the current AWS instance. It returns an IamResourceReport struct that contains any non-fatal
// errors that occurred during the execution of the subcommand. If the caller ARN cannot be retrieved, it will return an
// error because execution cannot proceed.
func IamDetails(ctx context.Context, cfg aws.Config) (IamResourceReport, error) {
	runningErrors := []string{}
	callerArn, err := sts.GetCallerArn(ctx, cfg)
	if err != nil {
		runningErrors = append(runningErrors, err.Error())
		return IamResourceReport{
			Errors: runningErrors,
		}, errors.New("failed to get caller ARN")
	}
	roleName, err := extractRoleNameFromARN(*callerArn)
	if err != nil {
		runningErrors = append(runningErrors, err.Error())
	}

	role, err := identity.GetRoleDetails(ctx, cfg, roleName)
	if err != nil {
		runningErrors = append(runningErrors, err.Error())
	}

	inlinePolicies, err := identity.GetInlinePoliciesForRole(ctx, cfg, roleName)
	if err != nil {
		runningErrors = append(runningErrors, err.Error())
	}

	attachedPolicyReport := identity.GetAttachedPoliciesForRole(ctx, cfg, roleName)
	runningErrors = append(runningErrors, attachedPolicyReport.Errors...)

	report := IamResourceReport{
		Role:             role,
		InlinePolicies:   inlinePolicies,
		AttachedPolicies: attachedPolicyReport.Policies,
		Errors:           runningErrors,
	}

	return report, nil
}

// extractRoleNameFromARN is a helper function that extracts the role name from an ARN. It is used to determine the IAM
// role associated with the current AWS instance.
func extractRoleNameFromARN(arn string) (string, error) {
	// Splitting the ARN by ":" and then "/"
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "", fmt.Errorf("invalid ARN format")
	}

	// The role info is expected to be in the last part
	roleInfo := parts[5]
	roleParts := strings.Split(roleInfo, "/")
	if len(roleParts) < 3 || roleParts[0] != "assumed-role" {
		return "", fmt.Errorf("invalid ARN role format")
	}

	// The role name is the part right after "assumed-role"
	roleName := roleParts[1]
	return roleName, nil
}
