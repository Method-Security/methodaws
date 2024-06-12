package rds

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/sts"
)

type AWSResources struct {
	RDSInstances []types.DBInstance `json:"rds_instances" yaml:"rds_instances"`
}

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
