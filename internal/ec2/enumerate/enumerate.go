package enumerate

import (
	"context"
	"fmt"

	ec2fern "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// InternalEnumerateEc2 enumerates EC2 resources based on the provided configuration
func InternalEnumerateEc2(ctx context.Context, awsConfig aws.Config, config ec2fern.Ec2EnumerateConfig) *ec2fern.Ec2EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting EC2 enumeration",
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Initialize report
	report := &ec2fern.Ec2EnumerateReport{
		Config: &config,
		Result: &ec2fern.Ec2EnumerateResult{},
	}

	var allInstances []*ec2fern.Ec2Instance
	var allErrors []string

	// Enumerate instances across all regions
	for _, region := range config.Regions {
		log.Info("Enumerating EC2 instances for region", svc1log.SafeParam("region", region))
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
		log.Info("Successfully enumerated EC2 instances",
			svc1log.SafeParam("totalInstances", len(allInstances)))
	} else {
		log.Info("No EC2 instances found across all regions")
		report.Result.Instances = []*ec2fern.Ec2Instance{}
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
		log.Warn("Errors encountered during EC2 enumeration",
			svc1log.SafeParam("errorCount", len(allErrors)))
	}

	log.Info("Completed EC2 enumeration",
		svc1log.SafeParam("totalInstances", len(allInstances)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// enumerateEc2ForRegion retrieves all EC2 instances for a specific region
func enumerateEc2ForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*ec2fern.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	var instances []*ec2fern.Ec2Instance
	var errors []string

	// Create region-specific config and client
	regionConfig := awsConfig.Copy()
	regionConfig.Region = region
	client := ec2.NewFromConfig(regionConfig)

	// Get all instances
	awsInstances, err := getAllInstances(ctx, client, region)
	if err != nil {
		errors = append(errors, err.Error())
		return instances, errors
	}

	log.Info("Processing EC2 instances",
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

// getAllInstances retrieves all EC2 instances in a region
func getAllInstances(ctx context.Context, client *ec2.Client, region string) ([]types.Instance, error) {
	var instances []types.Instance

	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
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
func processInstance(ctx context.Context, awsInstance types.Instance, region string) (*ec2fern.Ec2Instance, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Processing EC2 instance", svc1log.SafeParam("instanceId", awsInstance.InstanceId))
	var errors []string

	// Convert instance
	fernInstance, err := convertInstanceToFern(ctx, awsInstance, region)
	if err != nil {
		errors = append(errors, err...)
		return nil, errors
	}

	return fernInstance, errors
}
