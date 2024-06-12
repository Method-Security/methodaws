package ec2

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Instances struct {
	EC2Instances []types.Instance `json:"ec2_instances" yaml:"ec2_instances"`
}

type ResourceReport struct {
	Resources Instances `json:"resources" yaml:"resources"`
	Errors    []string  `json:"errors" yaml:"errors"`
}

type SecurityGroupReport struct {
	AccountID      string                `json:"account_id" yaml:"account_id"`
	SecurityGroups []types.SecurityGroup `json:"security_groups" yaml:"security_groups"`
	Errors         []string              `json:"errors" yaml:"errors"`
}
