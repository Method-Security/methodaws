package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	iam "github.com/Method-Security/methodaws/generated/go/iam"
	"github.com/aws/aws-sdk-go-v2/aws"
	iamaws "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateIamRoles retrieves all IAM roles with their attached policies
func enumerateIamRoles(ctx context.Context, cfg aws.Config) ([]*iam.IamRole, []string) {
	log := svc1log.FromContext(ctx)
	client := iamaws.NewFromConfig(cfg)
	var iamRoles []*iam.IamRole
	var errors []string

	// Get all roles
	roles, err := getAllRoles(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
		return iamRoles, errors
	}

	log.Info("Processing IAM roles", svc1log.SafeParam("roleCount", len(roles)))

	for _, role := range roles {
		if role.Arn == nil {
			log.Warn("role ARN is nil for role", svc1log.SafeParam("role", role))
			errors = append(errors, fmt.Sprintf("role ARN is nil for role %s", *role.RoleName))
			continue
		}
		if role.RoleName == nil {
			log.Warn("role name is nil for role", svc1log.SafeParam("role", role))
			errors = append(errors, fmt.Sprintf("role name is nil for role %s", *role.Arn))
			continue
		}
		iamRole, errs := processRole(ctx, client, role)
		if iamRole != nil {
			iamRoles = append(iamRoles, iamRole)
		}
		errors = append(errors, errs...)
	}

	return iamRoles, errors
}

// getAllRoles retrieves all IAM roles
func getAllRoles(ctx context.Context, client *iamaws.Client) ([]types.Role, error) {
	var roles []types.Role

	paginator := iamaws.NewListRolesPaginator(client, &iamaws.ListRolesInput{})
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}
		roles = append(roles, result.Roles...)
	}

	return roles, nil
}

// processRole converts a role and enriches it with policy information
func processRole(ctx context.Context, client *iamaws.Client, role types.Role) (*iam.IamRole, []string) {
	var errors []string

	// Create simplified IAM role
	iamRole := &iam.IamRole{
		Arn:      *role.Arn,
		RoleName: *role.RoleName,
	}

	// Add optional fields
	if role.CreateDate != nil {
		iamRole.CreateDate = role.CreateDate
	}

	// Add role last used if present
	if role.RoleLastUsed != nil {
		iamRole.RoleLastUsed = &iam.RoleLastUsed{
			LastUsedDate: role.RoleLastUsed.LastUsedDate,
			Region:       role.RoleLastUsed.Region,
		}
	}

	// Get attached policies
	attachedPolicies, errs := getAttachedPoliciesForRole(ctx, client, *role.RoleName)
	errors = append(errors, errs...)

	if len(attachedPolicies) > 0 {
		iamRole.AttachedPolicies = attachedPolicies
	}

	return iamRole, errors
}

// getAttachedPoliciesForRole gets all attached policies for a role with their documents
func getAttachedPoliciesForRole(ctx context.Context, client *iamaws.Client, roleName string) ([]*iam.AttachedPolicy, []string) {
	var attachedPolicies []*iam.AttachedPolicy
	var errors []string

	// List attached policies
	paginator := iamaws.NewListAttachedRolePoliciesPaginator(client, &iamaws.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to list attached policies for role %s: %v", roleName, err))
			break
		}

		for _, policy := range result.AttachedPolicies {
			if policy.PolicyArn != nil && policy.PolicyName != nil {
				attachedPolicy := &iam.AttachedPolicy{
					Arn:        *policy.PolicyArn,
					PolicyName: *policy.PolicyName,
				}

				// Determine if it's customer managed (Local scope) or AWS managed
				isCustomerManaged := !isAWSManagedPolicy(*policy.PolicyArn)
				attachedPolicy.IsCustomerManaged = &isCustomerManaged

				// Get policy document if it's customer managed
				if isCustomerManaged {
					if policy.PolicyArn == nil {
						errors = append(errors, fmt.Sprintf("policy ARN is nil for policy %s", *policy.PolicyName))
						continue
					}
					policyDoc, err := getPolicyDocument(ctx, client, *policy.PolicyArn)
					if err != nil {
						errors = append(errors, fmt.Sprintf("failed to get policy document for %s: %v", *policy.PolicyArn, err))
					} else {
						attachedPolicy.PolicyDocument = policyDoc
					}
				}

				attachedPolicies = append(attachedPolicies, attachedPolicy)
			}
		}
	}

	return attachedPolicies, errors
}

// getPolicyDocument retrieves the policy document for a given policy ARN
func getPolicyDocument(ctx context.Context, client *iamaws.Client, policyArn string) (*string, error) {
	// Get policy to find default version
	policy, err := client.GetPolicy(ctx, &iamaws.GetPolicyInput{
		PolicyArn: &policyArn,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy %s: %w", policyArn, err)
	}

	if policy.Policy.DefaultVersionId == nil {
		return nil, nil
	}

	// Get the policy version document
	version, err := client.GetPolicyVersion(ctx, &iamaws.GetPolicyVersionInput{
		PolicyArn: &policyArn,
		VersionId: policy.Policy.DefaultVersionId,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get policy version for %s: %w", policyArn, err)
	}

	if version.PolicyVersion.Document == nil {
		return nil, nil
	}

	// Decode and format the policy document
	decodedDoc, err := url.QueryUnescape(*version.PolicyVersion.Document)
	if err != nil {
		return version.PolicyVersion.Document, nil // Return original if decode fails
	}

	// Pretty format JSON if possible
	var jsonDoc interface{}
	if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
		if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
			prettyJSONStr := string(prettyJSON)
			return &prettyJSONStr, nil
		}
	}

	return &decodedDoc, nil
}

// isAWSManagedPolicy checks if a policy ARN represents an AWS managed policy
func isAWSManagedPolicy(arn string) bool {
	return len(arn) > 13 && arn[:13] == "arn:aws:iam::"
}
