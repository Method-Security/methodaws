package vpc

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type Instance struct {
	VPC types.Vpc `json:"vpc" yaml:"vpc"`
}

type Report struct {
	AccountID string     `json:"account_id" yaml:"account_id"`
	VPCs      []Instance `json:"vpcs" yaml:"vpcs"`
	Errors    []string   `json:"errors" yaml:"errors"`
}
