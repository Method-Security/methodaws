// Package rds provides functionality to enumerate and integrate AWS RDS resources.
package rds

import (
	"context"

	rdsfern "github.com/Method-Security/methodaws/generated/go/rds"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/rds/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateRDS(ctx context.Context, awsConfig aws.Config, config rdsfern.RdsEnumerateConfig) *rdsfern.RdsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting RDS enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &rdsfern.RdsEnumerateReport{
		Config: &config,
		Result: &rdsfern.RdsEnumerateResult{},
	}

	var allRDSInstances []*rdsfern.RdsInstance
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing RDS instances in region", svc1log.SafeParam("region", region))
		instances, errors := enumerateRDSForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating RDS instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allRDSInstances = append(allRDSInstances, instances...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed RDS instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("instanceCount", len(instances)))
	}

	// Marshal report
	if len(allRDSInstances) > 0 {
		report.Result.RdsInstances = allRDSInstances
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed RDS enumeration",
		svc1log.SafeParam("totalInstances", len(allRDSInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

func enumerateRDSForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*rdsfern.RdsInstance, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	rdsClient := rds.NewFromConfig(awsConfig)
	var errors []string

	// List RDS instances
	instances, err := listRDSInstances(ctx, rdsClient)
	if err != nil {
		errorMsg := "Failed to list RDS instances: " + err.Error()
		log.Error("Error listing RDS instances", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, errorMsg)
		return nil, errors
	}

	log.Info("Successfully listed RDS instances", svc1log.SafeParam("count", len(instances)))

	var rdsInstances []*rdsfern.RdsInstance
	for _, instance := range instances {
		rdsInstance := transformDBInstanceToFern(instance, region)
		rdsInstances = append(rdsInstances, rdsInstance)
	}

	return rdsInstances, errors
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

func transformDBInstanceToFern(instance types.DBInstance, region string) *rdsfern.RdsInstance {
	dbInstance := &rdsfern.DbInstance{}

	// Map basic fields
	dbInstance.DbInstanceIdentifier = instance.DBInstanceIdentifier
	dbInstance.DbInstanceClass = instance.DBInstanceClass
	dbInstance.Engine = instance.Engine
	dbInstance.EngineVersion = instance.EngineVersion
	dbInstance.DbInstanceStatus = instance.DBInstanceStatus
	dbInstance.MasterUsername = instance.MasterUsername
	dbInstance.DbName = instance.DBName
	dbInstance.AvailabilityZone = instance.AvailabilityZone
	dbInstance.DbInstanceArn = instance.DBInstanceArn
	dbInstance.DbiResourceId = instance.DbiResourceId

	// Map integer fields
	if instance.AllocatedStorage != nil {
		allocatedStorage := int(*instance.AllocatedStorage)
		dbInstance.AllocatedStorage = &allocatedStorage
	}
	if instance.DbInstancePort != nil {
		dbInstancePort := int(*instance.DbInstancePort)
		dbInstance.DbInstancePort = &dbInstancePort
	}
	if instance.Iops != nil {
		iops := int(*instance.Iops)
		dbInstance.Iops = &iops
	}

	// Map boolean fields
	dbInstance.MultiAz = instance.MultiAZ
	dbInstance.PubliclyAccessible = instance.PubliclyAccessible
	dbInstance.StorageEncrypted = instance.StorageEncrypted
	dbInstance.AutoMinorVersionUpgrade = instance.AutoMinorVersionUpgrade

	// Map endpoint
	if instance.Endpoint != nil {
		endpoint := &rdsfern.Endpoint{}
		if instance.Endpoint.Address != nil {
			endpoint.Address = instance.Endpoint.Address
		}
		if instance.Endpoint.Port != nil {
			port := int(*instance.Endpoint.Port)
			endpoint.Port = &port
		}
		if instance.Endpoint.HostedZoneId != nil {
			endpoint.HostedZoneId = instance.Endpoint.HostedZoneId
		}
		dbInstance.Endpoint = endpoint
	}

	// Map tags
	if len(instance.TagList) > 0 {
		var tags []*rdsfern.Tag
		for _, tag := range instance.TagList {
			fernTag := &rdsfern.Tag{}
			fernTag.Key = tag.Key
			fernTag.Value = tag.Value
			tags = append(tags, fernTag)
		}
		dbInstance.TagList = tags
	}

	return &rdsfern.RdsInstance{
		DbInstance: dbInstance,
		Region:     region,
	}
}
