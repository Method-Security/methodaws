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

// enumerateIamRoles retrieves all IAM roles available to the caller
func enumerateIamRoles(ctx context.Context, cfg aws.Config) ([]*iam.RoleResource, []string) {
	log := svc1log.FromContext(ctx)
	client := iamaws.NewFromConfig(cfg)
	var roleResources []*iam.RoleResource
	var errors []string

	// Get all roles
	roles, err := getAllRoles(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
		return roleResources, errors
	}

	log.Info("Processing IAM roles", svc1log.SafeParam("roleCount", len(roles)))

	for _, role := range roles {
		roleResource, errs := enrichRoleWithPolicies(ctx, client, role)
		if roleResource != nil {
			roleResources = append(roleResources, roleResource)
		}
		errors = append(errors, errs...)
	}

	return roleResources, errors
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

// enrichRoleWithPolicies enriches a role with its attached and inline policies
func enrichRoleWithPolicies(ctx context.Context, client *iamaws.Client, role types.Role) (*iam.RoleResource, []string) {
	var errors []string

	// Convert role to Fern format
	decodedRole, err := convertRoleToFern(role)
	if err != nil {
		errors = append(errors, err.Error())
		return nil, errors
	}

	// Get attached policies
	attachedPolicyArns, errs := getAttachedPolicyArns(ctx, client, *role.RoleName)
	errors = append(errors, errs...)

	// Get inline policies
	inlinePolicies, errs := getInlinePolicies(ctx, client, *role.RoleName)
	errors = append(errors, errs...)

	roleResource := &iam.RoleResource{
		Role:                 decodedRole,
		AttachedPoliciesArns: attachedPolicyArns,
		InlinePolicies:       inlinePolicies,
	}

	return roleResource, errors
}

// convertRoleToFern converts AWS IAM Role to Fern DecodedRole
func convertRoleToFern(role types.Role) (*iam.DecodedRole, error) {
	decodedRole := &iam.DecodedRole{
		Arn:                      role.Arn,
		AssumeRolePolicyDocument: role.AssumeRolePolicyDocument,
		CreateDate:               role.CreateDate,
		Description:              role.Description,
		MaxSessionDuration:       convertInt32PtrToIntPtr(role.MaxSessionDuration),
		Path:                     role.Path,
		RoleId:                   role.RoleId,
		RoleName:                 role.RoleName,
	}

	// Decode assume role policy document
	if role.AssumeRolePolicyDocument != nil {
		decodedDoc, err := url.QueryUnescape(*role.AssumeRolePolicyDocument)
		if err == nil {
			// Pretty format the JSON
			var jsonDoc interface{}
			if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
				if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
					prettyJSONStr := string(prettyJSON)
					decodedRole.DecodedAssumeRolePolicyDocument = &prettyJSONStr
				}
			}
		}
	}

	// Convert permissions boundary if present
	if role.PermissionsBoundary != nil {
		decodedRole.PermissionsBoundary = &iam.AttachedPermissionsBoundary{
			PermissionsBoundaryArn:  role.PermissionsBoundary.PermissionsBoundaryArn,
			PermissionsBoundaryType: (*string)(&role.PermissionsBoundary.PermissionsBoundaryType),
		}
	}

	// Convert role last used if present
	if role.RoleLastUsed != nil {
		decodedRole.RoleLastUsed = &iam.RoleLastUsed{
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
		decodedRole.Tags = tags
	}

	return decodedRole, nil
}

// getAttachedPolicyArns retrieves attached policy ARNs for a role
func getAttachedPolicyArns(ctx context.Context, client *iamaws.Client, roleName string) ([]string, []string) {
	var policyArns []string
	var errors []string

	paginator := iamaws.NewListAttachedRolePoliciesPaginator(client, &iamaws.ListAttachedRolePoliciesInput{
		RoleName: &roleName,
	})

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			errors = append(errors, err.Error())
			break
		}

		for _, policy := range result.AttachedPolicies {
			if policy.PolicyArn != nil {
				policyArns = append(policyArns, *policy.PolicyArn)
			}
		}
	}

	return policyArns, errors
}

// getInlinePolicies retrieves inline policies for a role
func getInlinePolicies(ctx context.Context, client *iamaws.Client, roleName string) ([]*iam.InlinePolicy, []string) {
	var inlinePolicies []*iam.InlinePolicy
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

		// Decode and format policy document
		var policyDoc string
		if policy.PolicyDocument != nil {
			decodedDoc, err := url.QueryUnescape(*policy.PolicyDocument)
			if err == nil {
				// Pretty format the JSON
				var jsonDoc interface{}
				if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
					if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
						policyDoc = string(prettyJSON)
					} else {
						policyDoc = decodedDoc
					}
				} else {
					policyDoc = decodedDoc
				}
			}
		}

		inlinePolicies = append(inlinePolicies, &iam.InlinePolicy{
			Name:   policyName,
			Policy: policyDoc,
		})
	}

	return inlinePolicies, errors
}

// convertInt32PtrToIntPtr converts *int32 to *int for compatibility
func convertInt32PtrToIntPtr(val *int32) *int {
	if val == nil {
		return nil
	}
	converted := int(*val)
	return &converted
}
