package iam

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type DecodedPolicyVersion struct {
	CreateDate *time.Time `json:"createDate" yaml:"createDate"`

	// The policy document, decoded from its AWS provided URL encoding to a stringified JSON object
	Document *string `json:"document" yaml:"document"`

	IsDefaultVersion bool    `json:"isDefaultVersion" yaml:"isDefaultVersion"`
	VersionID        *string `json:"versionId" yaml:"versionId"`
}

type PolicyResource struct {
	Policy        types.Policy         `json:"policy" yaml:"policy"`
	PolicyVersion DecodedPolicyVersion `json:"policyVersion" yaml:"policyVersion"`
}

type PolicyReport struct {
	Policies []PolicyResource `json:"policies" yaml:"policies"`

	Errors []string `json:"errors" yaml:"errors"`
}

type InlinePolicy struct {
	PolicyName string `json:"policyName" yaml:"policyName"`
	Policy     string `json:"policy" yaml:"policy"`
}

type DecodedRole struct {
	Role                            types.Role `json:"role" yaml:"role"`
	DecodedAssumeRolePolicyDocument *string    `json:"decodedAssumeRolePolicyDocument" yaml:"decodedAssumeRolePolicyDocument"`
}

type RoleResource struct {
	Role                 DecodedRole     `json:"role" yaml:"role"`
	AttachedPoliciesArns []string        `json:"attachedPoliciesArns" yaml:"attachedPoliciesArns"`
	InlinePolicies       []*InlinePolicy `json:"inlinePolicies" yaml:"inlinePolicies"`
}

type RoleReport struct {
	Roles    []RoleResource `json:"roles" yaml:"roles"`
	Policies PolicyReport   `json:"policies" yaml:"policies"`
	Errors   []string       `json:"errors" yaml:"errors"`
}
