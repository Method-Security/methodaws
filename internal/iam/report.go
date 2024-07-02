package iam

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// DecodedPolicyVersion is a struct that contains the decoded policy version details. This struct provides us with a
// mechanism to decode the policy document from its AWS provided URL encoding to a stringified JSON object.
type DecodedPolicyVersion struct {
	CreateDate *time.Time `json:"create_date" yaml:"create_date"`

	// The policy document, decoded from its AWS provided URL encoding to a stringified JSON object
	Document *string `json:"document" yaml:"document"`

	IsDefaultVersion bool    `json:"is_default_version" yaml:"is_default_version"`
	VersionID        *string `json:"version_id" yaml:"version_id"`
}

// PolicyResource is a struct that contains the policy and policy version details. This struct is used to represent the
// native AWS policy response alongside the decoded policy version.
type PolicyResource struct {
	Policy        types.Policy         `json:"policy" yaml:"policy"`
	PolicyVersion DecodedPolicyVersion `json:"policy_version" yaml:"policy_version"`
}

// PolicyReport is a struct that contains a slice of PolicyResource structs and any errors that occurred during the
// collection of the policies. This struct is used to represent the output of the `methodaws iam policies` subcommand.
type PolicyReport struct {
	Policies []PolicyResource `json:"policies" yaml:"policies"`

	Errors []string `json:"errors" yaml:"errors"`
}

// InlinePolicy is a struct that contains the policy name and policy document. This struct is used to represent the
// inline policies that are attached to an IAM role.
type InlinePolicy struct {
	PolicyName string `json:"policy_name" yaml:"policy_name"`
	Policy     string `json:"policy" yaml:"policy"`
}

// DecodedRole is a struct that contains the role details and the decoded assume role policy document. This struct is
// used to represent the role details of an IAM role in a more human-readable format.
type DecodedRole struct {
	Role                            types.Role `json:"role" yaml:"role"`
	DecodedAssumeRolePolicyDocument *string    `json:"decoded_assume_role_policy_document" yaml:"decoded_assume_role_policy_document"`
}

// RoleResource is a struct that contains the role details, attached policies, and inline policies for an IAM role. This
// struct is used to represent the output of the `methodaws iam role` subcommand, providing the most holistic information
// possible about all of the policies that a Role has available to it.
type RoleResource struct {
	Role                 DecodedRole     `json:"role" yaml:"role"`
	AttachedPoliciesArns []string        `json:"attached_policies_arns" yaml:"attached_policies_arns"`
	InlinePolicies       []*InlinePolicy `json:"inline_policies" yaml:"inline_policies"`
}

// AWSResources is a struct that contains a slice of RoleResource structs and a PolicyReport. This struct is used to
// represent the output of the `methodaws iam` subcommand, easing data integration and providing a more holistic view of
// all of the IAM roles and policies that are available to the current AWS account.
type AWSResources struct {
	Roles    []RoleResource `json:"roles" yaml:"roles"`
	Policies PolicyReport   `json:"policy_report" yaml:"policy_report"`
}

// AWSResourceReport is a struct that contains The Resources and Errors.. This struct is used to
// represent the output of the `methodaws iam role` subcommand, easing data integration and providing a more holistic
// view of all of the IAM roles and policies that are available to the current AWS account.
type AWSResourceReport struct {
	Resources AWSResources `json:"resources" yaml:"resources"`
	Errors    []string     `json:"errors" yaml:"errors"`
}
