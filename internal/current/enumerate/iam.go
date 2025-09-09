package current

import (
	"context"
	"fmt"
	"strings"

	currentfern "github.com/Method-Security/methodaws/generated/go/current"
	iam "github.com/Method-Security/methodaws/generated/go/iam"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamaws "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateCurrentIam enumerates the current IAM role details, inline policies, and attached policies
func EnumerateCurrentIam(ctx context.Context, awsConfig aws.Config, config currentfern.CurrentIamConfig) *currentfern.CurrentIamReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting current IAM enumeration",
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &currentfern.CurrentIamReport{
		Config: &config,
		Result: &currentfern.CurrentIamResult{
			Resource: &currentfern.CurrentIamResource{},
		},
	}

	var allErrors []string

	// Get caller ARN to determine role name
	callerArn, err := sts.GetCallerArn(ctx, awsConfig)
	if err != nil {
		allErrors = append(allErrors, err.Error())
		report.Errors = allErrors
		return report
	}

	roleName, err := extractRoleNameFromARN(*callerArn)
	if err != nil {
		allErrors = append(allErrors, err.Error())
		report.Errors = allErrors
		return report
	}

	log.Info("Enumerating current IAM role", svc1log.SafeParam("roleName", roleName))

	client := iamaws.NewFromConfig(awsConfig)

	// Get role details
	role, err := getRoleDetails(ctx, client, roleName)
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}

	// Get inline policies
	inlinePolicies, errs := getInlinePolicies(ctx, client, roleName)
	allErrors = append(allErrors, errs...)

	// Get attached policies
	attachedPolicies, errs := getAttachedPolicies(ctx, client, roleName)
	allErrors = append(allErrors, errs...)

	// Populate report
	report.Result.Resource.Role = role
	report.Result.Resource.InlinePolicies = inlinePolicies
	report.Result.Resource.AttachedPolicies = attachedPolicies

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed current IAM enumeration",
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// getRoleDetails gets the current role details
func getRoleDetails(ctx context.Context, client *iamaws.Client, roleName string) (*currentfern.IamRole, error) {
	roleOutput, err := client.GetRole(ctx, &iamaws.GetRoleInput{
		RoleName: &roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role details: %w", err)
	}

	return convertRoleToCurrentFern(roleOutput.Role), nil
}

// convertRoleToCurrentFern converts AWS IAM Role to current Fern IamRole
func convertRoleToCurrentFern(role *types.Role) *currentfern.IamRole {
	if role == nil || role.Arn == nil {
		return nil
	}

	iamRole := &currentfern.IamRole{
		Arn:                      *role.Arn,
		AssumeRolePolicyDocument: role.AssumeRolePolicyDocument,
		CreateDate:               role.CreateDate,
		Description:              role.Description,
		MaxSessionDuration:       convertInt32PtrToIntPtr(role.MaxSessionDuration),
		Path:                     role.Path,
		RoleId:                   role.RoleId,
		RoleName:                 role.RoleName,
	}

	// Convert permissions boundary if present
	if role.PermissionsBoundary != nil {
		iamRole.PermissionsBoundary = &iam.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  role.PermissionsBoundary.PermissionsBoundaryArn,
			PermissionsBoundaryType: (*string)(&role.PermissionsBoundary.PermissionsBoundaryType),
		}
	}

	// Convert role last used if present
	if role.RoleLastUsed != nil {
		iamRole.RoleLastUsed = &iam.RoleLastUsed{
			LastUsedDate: role.RoleLastUsed.LastUsedDate,
			Region:       role.RoleLastUsed.Region,
		}
	}

	// Convert tags
	if len(role.Tags) > 0 {
		var tags []*iam.RoleTag
		for _, tag := range role.Tags {
			tags = append(tags, &iam.RoleTag{
				Key:   *tag.Key,
				Value: *tag.Value,
			})
		}
		iamRole.Tags = tags
	}

	return iamRole
}

// getInlinePolicies gets inline policies for the role
func getInlinePolicies(ctx context.Context, client *iamaws.Client, roleName string) ([]*currentfern.RolePolicy, []string) {
	var inlinePolicies []*currentfern.RolePolicy
	var errors []string

	// Get policy names
	policyNames, err := client.ListRolePolicies(ctx, &iamaws.ListRolePoliciesInput{
		RoleName: &roleName,
	})
	if err != nil {
		errors = append(errors, err.Error())
		return inlinePolicies, errors
	}

	// Get each policy document
	for _, policyName := range policyNames.PolicyNames {
		policy, err := client.GetRolePolicy(ctx, &iamaws.GetRolePolicyInput{
			RoleName:   &roleName,
			PolicyName: &policyName,
		})
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		inlinePolicies = append(inlinePolicies, &currentfern.RolePolicy{
			PolicyDocument: policy.PolicyDocument,
			PolicyName:     policy.PolicyName,
			RoleName:       policy.RoleName,
		})
	}

	return inlinePolicies, errors
}

// getAttachedPolicies gets attached policies for the role
func getAttachedPolicies(ctx context.Context, client *iamaws.Client, roleName string) ([]*iam.PolicyResource, []string) {
	var attachedPolicies []*iam.PolicyResource
	var errors []string

	// Get attached policy ARNs
	paginator := iamaws.NewListAttachedRolePoliciesPaginator(client, &iamaws.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, err.Error())
			break
		}

		// Get detailed information for each attached policy
		for _, attachedPolicy := range result.AttachedPolicies {
			if attachedPolicy.PolicyArn == nil {
				continue
			}

			policyDetails, err := client.GetPolicy(ctx, &iamaws.GetPolicyInput{
				PolicyArn: attachedPolicy.PolicyArn,
			})
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Convert to Fern format
			policyResource := convertPolicyToFern(policyDetails.Policy)

			// Get the default version document if available
			if policyDetails.Policy.DefaultVersionId != nil {
				version, err := client.GetPolicyVersion(ctx, &iamaws.GetPolicyVersionInput{
					PolicyArn: attachedPolicy.PolicyArn,
					VersionId: policyDetails.Policy.DefaultVersionId,
				})
				if err != nil {
					errors = append(errors, err.Error())
				} else {
					decodedVersion, err := convertPolicyVersionToFern(version.PolicyVersion)
					if err != nil {
						errors = append(errors, err.Error())
					} else {
						policyResource.PolicyVersion = decodedVersion
					}
				}
			}

			attachedPolicies = append(attachedPolicies, policyResource)
		}
	}

	return attachedPolicies, errors
}

// convertPolicyToFern converts AWS IAM Policy to Fern PolicyResource (reusing from iam package)
func convertPolicyToFern(policy *types.Policy) *iam.PolicyResource {
	if policy == nil {
		return nil
	}

	policyResource := &iam.PolicyResource{
		Arn:                           policy.Arn,
		AttachmentCount:               convertInt32PtrToIntPtr(policy.AttachmentCount),
		CreateDate:                    policy.CreateDate,
		DefaultVersionId:              policy.DefaultVersionId,
		Description:                   policy.Description,
		IsAttachable:                  &policy.IsAttachable,
		Path:                          policy.Path,
		PermissionsBoundaryUsageCount: convertInt32PtrToIntPtr(policy.PermissionsBoundaryUsageCount),
		PolicyId:                      policy.PolicyId,
		PolicyName:                    policy.PolicyName,
		UpdateDate:                    policy.UpdateDate,
	}

	// Convert tags
	if len(policy.Tags) > 0 {
		var tags []*iam.PolicyTag
		for _, tag := range policy.Tags {
			tags = append(tags, &iam.PolicyTag{
				Key:   *tag.Key,
				Value: *tag.Value,
			})
		}
		policyResource.Tags = tags
	}

	return policyResource
}

// extractRoleNameFromARN extracts the role name from an ARN
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

// convertInt32PtrToIntPtr converts *int32 to *int for compatibility
func convertInt32PtrToIntPtr(val *int32) *int {
	if val == nil {
		return nil
	}
	converted := int(*val)
	return &converted
}
