package ec2

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// Instances represents all of the EC2 instances that were returned during the reporting process
type Instances struct {
	EC2Instances []types.Instance `json:"ec2_instances" yaml:"ec2_instances"`
}

// ResourceReport contains the EC2 instances and any errors that occurred during the execution of the
// `methodaws ec2 enumerate` subcommand. Non-fatal errors are stored in the Errors field.
type ResourceReport struct {
	Resources Instances `json:"resources" yaml:"resources"`
	Errors    []string  `json:"errors" yaml:"errors"`
}

// SecurityGroupReport contains the security groups and any errors that occurred during the execution of the
// `methodaws securitygroup enumerate` subcommand.
// Non-fatal errors are stored in the Errors field.
type SecurityGroupReport struct {
	AccountID      string                `json:"account_id" yaml:"account_id"`
	SecurityGroups []types.SecurityGroup `json:"security_groups" yaml:"security_groups"`
	Errors         []string              `json:"errors" yaml:"errors"`
}
