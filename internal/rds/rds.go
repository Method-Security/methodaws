// The rds package provides functionality to enumerate and integrate AWS RDS resources.
package rds

import (
	"context"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
)

// AWSResources contains the RDS instances that were enumerated.
type AWSResources struct {
	RDSInstances []types.DBInstance `json:"rds_instances" yaml:"rds_instances"`
}

// AWSResourceReport contains the account ID that the RDS instances were discovered in, the resources themselves,
// and any non-fatal errors that occurred during the execution of the `methodaws rds enumerate` subcommand.
type AWSResourceReport struct {
	AccountID string       `json:"account_id" yaml:"account_id"`
	Resources AWSResources `json:"resources" yaml:"resources"`
	Errors    []string     `json:"errors" yaml:"errors"`
}

func listRDSInstances(ctx context.Context, rdsClient *rds.Client) ([]types.DBInstance, error) {
	var instances []types.DBInstance
	paginator := rds.NewDescribeDBInstancesPaginator(rdsClient, &rds.DescribeDBInstancesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		instances = append(instances, page.DBInstances...)
	}

	return instances, nil
}

// EnumerateRds retrieves all RDS instances available to the caller and returns an AWSResourceReport struct
func EnumerateRds(ctx context.Context, cfg aws.Config) (*AWSResourceReport, error) {
	rdsClient := rds.NewFromConfig(cfg)
	resources := AWSResources{}
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{Errors: errors}, err
	}

	instances, err := listRDSInstances(ctx, rdsClient)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		resources.RDSInstances = instances
	}

	report := AWSResourceReport{
		AccountID: *accountID,
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}
