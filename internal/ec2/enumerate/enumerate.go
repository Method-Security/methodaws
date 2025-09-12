package enumerate

import (
	"context"
	"fmt"

	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2aws "github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// InternalEnumerateEc2 enumerates ec2aws resources based on the provided configuration
func InternalEnumerateEc2(ctx context.Context, awsConfig aws.Config, config ec2.Ec2EnumerateConfig) *ec2.Ec2EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting ec2aws enumeration",
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Initialize report
	report := &ec2.Ec2EnumerateReport{
		Config: &config,
		Result: &ec2.Ec2EnumerateResult{},
	}

	var allInstances []*ec2.Ec2Instance
	var allErrors []string

	// Enumerate instances across all regions
	for _, region := range config.Regions {
		log.Info("Enumerating ec2 instances for region", svc1log.SafeParam("region", region))
		instances, errs := enumerateEc2ForRegion(ctx, awsConfig, region)

		if len(instances) > 0 {
			allInstances = append(allInstances, instances...)
		}
		if len(errs) > 0 {
			allErrors = append(allErrors, errs...)
		}
	}

	// Populate report
	if len(allInstances) > 0 {
		report.Result.Instances = allInstances
		log.Info("Successfully enumerated ec2 instances",
			svc1log.SafeParam("totalInstances", len(allInstances)))
	} else {
		log.Info("No ec2 instances found across all regions")
		report.Result.Instances = []*ec2.Ec2Instance{}
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
		log.Warn("Errors encountered during ec2 enumeration",
			svc1log.SafeParam("errorCount", len(allErrors)))
	}

	log.Info("Completed ec2 enumeration",
		svc1log.SafeParam("totalInstances", len(allInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// enumerateEc2ForRegion retrieves all ec2 instances for a specific region
func enumerateEc2ForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*ec2.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	var instances []*ec2.Ec2Instance
	var errors []string

	// Create region-specific config and client
	regionConfig := awsConfig.Copy()
	regionConfig.Region = region
	client := ec2aws.NewFromConfig(regionConfig)

	// Get all instances
	awsInstances, err := getAllInstances(ctx, client, region)
	if err != nil {
		errors = append(errors, err.Error())
		return instances, errors
	}

	log.Info("Processing ec2aws instances",
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("instanceCount", len(awsInstances)))

	// Process each instance
	for _, awsInstance := range awsInstances {
		if awsInstance.InstanceId == nil {
			log.Warn("Instance ID is nil for instance", svc1log.SafeParam("instance", awsInstance))
			errors = append(errors, "Instance ID is nil")
			continue
		}
		instance, errs := processInstance(ctx, awsInstance, region)
		if instance != nil {
			instances = append(instances, instance)
		}
		errors = append(errors, errs...)
	}

	return instances, errors
}

// getAllInstances retrieves all ec2aws instances in a region
func getAllInstances(ctx context.Context, client *ec2aws.Client, region string) ([]types.Instance, error) {
	var instances []types.Instance

	paginator := ec2aws.NewDescribeInstancesPaginator(client, &ec2aws.DescribeInstancesInput{})
	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list instances in region %s: %w", region, err)
		}

		// Extract instances from reservations
		for _, reservation := range result.Reservations {
			instances = append(instances, reservation.Instances...)
		}
	}

	return instances, nil
}

// processInstance converts an AWS instance to Fern format
func processInstance(ctx context.Context, awsInstance types.Instance, region string) (*ec2.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Processing ec2aws instance", svc1log.SafeParam("instanceId", awsInstance.InstanceId))
	var errors []string

	// Convert instance
	fernInstance, err := convertInstanceToFern(ctx, awsInstance, region)
	if err != nil {
		errors = append(errors, err...)
		return nil, errors
	}

	return fernInstance, errors
}
