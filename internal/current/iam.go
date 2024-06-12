package current

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	identity "gitlab.com/method-security/cyber-tools/methodaws/internal/iam"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/sts"
)

type IamResourceReport struct {
	InlinePolicies   []*iam.GetRolePolicyOutput `json:"inlinePolicies" yaml:"inlinePolicies"`
	AttachedPolicies []identity.PolicyResource  `json:"attachedPolicies" yaml:"attachedPolicies"`
	Role             *types.Role                `json:"role" yaml:"role"`
	Errors           []string                   `json:"errors" yaml:"errors"`
}

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
