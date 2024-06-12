package iam

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func GetInlinePoliciesForRole(ctx context.Context, cfg aws.Config, roleName string) ([]*iam.GetRolePolicyOutput, error) {
	client := iam.NewFromConfig(cfg)
	rolePolicyOutput, err := client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		return nil, err
	}
	policyNames := rolePolicyOutput.PolicyNames

	policies := make([]*iam.GetRolePolicyOutput, 0)

	for _, policyName := range policyNames {
		policy, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: &roleName, PolicyName: &policyName})
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

func GetAttachedPoliciesForRole(ctx context.Context, cfg aws.Config, roleName string) *PolicyReport {
	client := iam.NewFromConfig(cfg)
	policies := make([]PolicyResource, 0)
	errors := make([]string, 0)

	attachedPolicyOutput, err := client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: &roleName})
	if err != nil {
		errors = append(errors, err.Error())
	}

	if attachedPolicyOutput == nil {
		return &PolicyReport{
			Policies: policies,
			Errors:   errors,
		}
	}
	for _, policy := range attachedPolicyOutput.AttachedPolicies {
		policyOutput, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: policy.PolicyArn})
		if err != nil {
			errors = append(errors, err.Error())
		}
		if policyOutput == nil || policyOutput.Policy == nil || policyOutput.Policy.Arn == nil {
			errors = append(errors, fmt.Sprintf("Failed to get policy for attached policy %s", *policy.PolicyArn))
			continue
		}

		policyVersionOutput, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policy.PolicyArn, VersionId: policyOutput.Policy.DefaultVersionId})
		if err != nil {
			errors = append(errors, err.Error())
		}

		decodedPolicyVersion, err := decodePolicyVersion(*policyVersionOutput.PolicyVersion)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		policies = append(policies, PolicyResource{
			Policy:        *policyOutput.Policy,
			PolicyVersion: decodedPolicyVersion,
		})
	}

	return &PolicyReport{
		Policies: policies,
		Errors:   errors,
	}
}

func decodePolicyVersion(policyVersion types.PolicyVersion) (DecodedPolicyVersion, error) {
	decodedDocument, err := decodeDocument(policyVersion.Document)
	if err != nil {
		return DecodedPolicyVersion{}, err
	}
	minifiedDocument, err := minifyJSON(*decodedDocument)
	if err != nil {
		return DecodedPolicyVersion{}, err
	}

	return DecodedPolicyVersion{
		CreateDate:       policyVersion.CreateDate,
		Document:         minifiedDocument,
		IsDefaultVersion: policyVersion.IsDefaultVersion,
		VersionID:        policyVersion.VersionId,
	}, nil
}

func decodeDocument(policyDocument *string) (*string, error) {
	// Decodes the URL encoded policy document and returns stringified JSON
	decodedDocument, err := url.QueryUnescape(*policyDocument)
	if err != nil {
		return nil, err
	}
	return &decodedDocument, nil
}

func minifyJSON(jsonStr string) (*string, error) {
	var jsonObj interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonObj)
	if err != nil {
		return nil, err
	}
	minifiedJSONBytes, err := json.Marshal(jsonObj)
	if err != nil {
		return nil, err
	}

	minifiedJSON := string(minifiedJSONBytes)

	return &minifiedJSON, nil
}
