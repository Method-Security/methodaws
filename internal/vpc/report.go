// The vpc package provides the data structures and logic necessary to enumerate and integrate AWS VPC resources.
package vpc

import (
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// The Instance struct contains the VPC data that was enumerated, wrapping the AWS values
type Instance struct {
	VPC types.Vpc `json:"vpc" yaml:"vpc"`
}

// The Report struct contains the account ID that the VPCs were discovered in, the resources themselves,
// and any non-fatal errors that occurred during the execution of the `methodaws vpc enumerate` subcommand.
type Report struct {
	AccountID string     `json:"account_id" yaml:"account_id"`
	VPCs      []Instance `json:"vpcs" yaml:"vpcs"`
	Errors    []string   `json:"errors" yaml:"errors"`
}
