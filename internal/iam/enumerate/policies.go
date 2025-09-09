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

// enumerateIamPolicies retrieves all IAM policies available to the caller
func enumerateIamPolicies(ctx context.Context, cfg aws.Config) (*iam.PolicyReport, []string) {
	log := svc1log.FromContext(ctx)
	client := iamaws.NewFromConfig(cfg)
	var policyResources []*iam.PolicyResource
	var errors []string

	// Get all policies (customer managed and AWS managed)
	policies, err := getAllPolicies(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
		return &iam.PolicyReport{
			Policies: policyResources,
		}, errors
	}

	log.Info("Processing IAM policies", svc1log.SafeParam("policyCount", len(policies)))

	for _, policy := range policies {
		policyResource, errs := enrichPolicyWithVersion(ctx, client, policy)
		if policyResource != nil {
			policyResources = append(policyResources, policyResource)
		}
		errors = append(errors, errs...)
	}

	return &iam.PolicyReport{
		Policies: policyResources,
	}, errors
}

// getAllPolicies retrieves all IAM policies
func getAllPolicies(ctx context.Context, client *iamaws.Client) ([]types.Policy, error) {
	var policies []types.Policy

	// Get customer managed policies
	customerPaginator := iamaws.NewListPoliciesPaginator(client, &iamaws.ListPoliciesInput{
		Scope: types.PolicyScopeTypeLocal,
	})
	for customerPaginator.HasMorePages() {
		result, err := customerPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list customer managed policies: %w", err)
		}
		policies = append(policies, result.Policies...)
	}

	awsPaginator := iamaws.NewListPoliciesPaginator(client, &iamaws.ListPoliciesInput{
		Scope: types.PolicyScopeTypeAws,
	})
	for awsPaginator.HasMorePages() {
		result, err := awsPaginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list AWS managed policies: %w", err)
		}
		policies = append(policies, result.Policies...)
	}

	return policies, nil
}

// enrichPolicyWithVersion enriches a policy with its default version document
func enrichPolicyWithVersion(ctx context.Context, client *iamaws.Client, policy types.Policy) (*iam.PolicyResource, []string) {
	var errors []string

	// Convert policy to Fern format
	policyResource := convertPolicyToFern(policy)

	// Get the default version document
	if policy.DefaultVersionId != nil {
		version, err := client.GetPolicyVersion(ctx, &iamaws.GetPolicyVersionInput{
			PolicyArn: policy.Arn,
			VersionId: policy.DefaultVersionId,
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

	return policyResource, errors
}

// convertPolicyToFern converts AWS IAM Policy to Fern PolicyResource
func convertPolicyToFern(policy types.Policy) *iam.PolicyResource {
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

// convertPolicyVersionToFern converts AWS IAM PolicyVersion to Fern DecodedPolicyVersion
func convertPolicyVersionToFern(version *types.PolicyVersion) (*iam.DecodedPolicyVersion, error) {
	decodedVersion := &iam.DecodedPolicyVersion{
		CreateDate:       version.CreateDate,
		IsDefaultVersion: &version.IsDefaultVersion,
		VersionId:        version.VersionId,
	}

	// Decode and format policy document
	if version.Document != nil {
		decodedDoc, err := url.QueryUnescape(*version.Document)
		if err != nil {
			return nil, fmt.Errorf("failed to decode policy document: %w", err)
		}

		// Pretty format the JSON
		var jsonDoc interface{}
		if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
			if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
				prettyJSONStr := string(prettyJSON)
				decodedVersion.Document = &prettyJSONStr
			} else {
				decodedVersion.Document = &decodedDoc
			}
		} else {
			decodedVersion.Document = &decodedDoc
		}
	}

	return decodedVersion, nil
}
