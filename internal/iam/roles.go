package iam

import (
	"context"
	"errors"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/Method-Security/methodaws/internal/sts"
)

// EnumerateIamRoles retrieves all IAM roles available to the caller. It returns a AWSResourceReport struct that contains all
// roles, attached or inline policies, and any non-fatal errors that occurred during the execution of the function.
func EnumerateIamRoles(ctx context.Context, cfg aws.Config) (*AWSResourceReport, error) {
	client := iam.NewFromConfig(cfg)
	policies := []PolicyResource{}
	report := AWSResourceReport{
		Resources: AWSResources{},
		Errors:    []string{},
	}
	report.Resources.Roles = []RoleResource{}

	// Get the account ID
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		report.AccountID = aws.ToString(accountID)
		return &report, nil
		
	}

	roles, err := GetAllRoles(ctx, client)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return &report, nil
	}

	for _, role := range roles {
		roleResource, attachedPolicies, err := EnrichRoleWithPolicies(ctx, cfg, &role)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			continue
		}
		if attachedPolicies != nil {
			policies = append(policies, attachedPolicies...)
		}

		report.Resources.Roles = append(report.Resources.Roles, roleResource)
	}

	report.Resources.Policies = PolicyReport{
		Policies: distinctPoliciesFromResource(policies),
		Errors:   []string{},
	}
	report.AccountID = aws.ToString(accountID)

	return &report, nil
}

// EnrichRoleWithPolicies retrieves the attached and inline policies for a given IAM role. It returns a RoleResource struct
// that contains the role, any attached policies, and any inline policies. It also returns a slice of PolicyResource structs
// that contain the attached policies for the role.
func EnrichRoleWithPolicies(ctx context.Context, cfg aws.Config, role *types.Role) (RoleResource, []PolicyResource, error) {

	decodedRole, err := decodeRole(role)
	if err != nil {
		return RoleResource{}, nil, err
	}

	roleResource := RoleResource{
		Role:                 *decodedRole,
		AttachedPoliciesArns: []string{},
		InlinePolicies:       []*InlinePolicy{},
	}

	policyReport := GetAttachedPoliciesForRole(ctx, cfg, *role.RoleName)
	if policyReport == nil {
		return roleResource, nil, errors.New("failed to get attached policies for role")
	}

	for _, policy := range policyReport.Policies {
		roleResource.AttachedPoliciesArns = append(roleResource.AttachedPoliciesArns, *policy.Policy.Arn)
	}

	inlinePolicies, err := GetInlinePoliciesForRole(ctx, cfg, *role.RoleName)
	if err != nil {
		return roleResource, nil, err
	}

	for _, inlinePolicy := range inlinePolicies {
		decoded, err := decodeDocument(inlinePolicy.PolicyDocument)
		if err != nil {
			continue
		}
		minified, err := minifyJSON(*decoded)
		if err != nil {
			continue
		}

		roleResource.InlinePolicies = append(roleResource.InlinePolicies, &InlinePolicy{
			PolicyName: *inlinePolicy.PolicyName,
			Policy:     *minified,
		})
	}

	return roleResource, policyReport.Policies, nil
}

// GetRoleDetails uses the AWS SDK to retrieve and return a Role for the provided role name.
func GetRoleDetails(ctx context.Context, cfg aws.Config, roleName string) (*types.Role, error) {
	client := iam.NewFromConfig(cfg)
	roleOutput, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: &roleName})
	if err != nil {
		return nil, err
	}
	return roleOutput.Role, nil
}

// GetAllRoles retrieves all Roles that are available to the caller.
func GetAllRoles(ctx context.Context, client *iam.Client) ([]types.Role, error) {
	roles := []types.Role{}

	output, err := client.ListRoles(ctx, &iam.ListRolesInput{})
	if err != nil {
		return nil, err
	}

	roles = append(roles, output.Roles...)

	for output.IsTruncated {
		output, err = client.ListRoles(ctx, &iam.ListRolesInput{Marker: output.Marker})
		if err != nil {
			return nil, err
		}
		roles = append(roles, output.Roles...)
	}

	return roles, nil
}

// Given a slice of PolicyResource, return a slice of unique PolicyResources.
func distinctPoliciesFromResource(policies []PolicyResource) []PolicyResource {
	policiesMap := make(map[string]PolicyResource)
	for _, policy := range policies {
		policiesMap[*policy.Policy.Arn] = policy
	}

	uniquePolicies := []PolicyResource{}
	for _, policy := range policiesMap {
		uniquePolicies = append(uniquePolicies, policy)
	}
	return uniquePolicies
}

// Decode the AssumeRolePolicyDocument for a given Role.
func decodeRole(role *types.Role) (*DecodedRole, error) {
	decodedAssumeRolePolicyDocument, err := decodeDocument(role.AssumeRolePolicyDocument)
	if err != nil {
		return nil, err
	}
	minified, err := minifyJSON(*decodedAssumeRolePolicyDocument)
	if err != nil {
		return nil, err
	}

	return &DecodedRole{
		Role:                            *role,
		DecodedAssumeRolePolicyDocument: minified,
	}, nil
}
