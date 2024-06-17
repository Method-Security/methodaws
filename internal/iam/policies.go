// Package iam contains functions that interact with the AWS IAM service along with the data structures necessary
// to integrate this data cleanly.
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

// GetInlinePoliciesForRole captures any policies that have been inlined within a given IAM role. It returns a slice of
// the AWS GetRolePolicyOutput struct. If the client is unable to list policies for the role, it will return an error.
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

// GetAttachedPoliciesForRole captures  any policies that have been attached to a given IAM role. It returns a
// PolicyReport struct that contains the attached policies and any non-fatal errors that occurred during the execution
// of the function.
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

// A utility function that decodes a policy version. It returns a DecodedPolicyVersion struct that contains the decoded
// policy version and any errors that occurred during the decoding process.
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

// A utility function that decodes a policy document. The AWS API returns the policy document as a URL encoded string
// that needs to be decoded before it can be used.
func decodeDocument(policyDocument *string) (*string, error) {
	// Decodes the URL encoded policy document and returns stringified JSON
	decodedDocument, err := url.QueryUnescape(*policyDocument)
	if err != nil {
		return nil, err
	}
	return &decodedDocument, nil
}

// A utility function that minifies all returned Policy JSON documents. This is necessary because the decoded JSON
// that is returned via the AWS APIs includes whitespace and newlines that are not necessary for the output.
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
