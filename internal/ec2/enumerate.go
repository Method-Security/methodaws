package ec2

import (
	// Standard
	"context"
	"fmt"
	"strings"

	// Generated
	ec2fern "github.com/Method-Security/methodaws/generated/go/ec2"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateEc2ForRegion enumerates all of the EC2 instances that the caller has access to. It returns a Ec2ResourceReport struct
// that contains the EC2 instances and any non-fatal errors that occurred during the execution of the subcommand.
func enumerateEc2ForRegion(ctx context.Context, awsConfig aws.Config, region string) (*ec2fern.Ec2EnumerateResult, []string, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating EC2 instances for region", svc1log.SafeParam("region", region))

	errors := []string{}
	ec2Instances := []*ec2fern.InstanceWithIamRole{}

	// Create a region-specific AWS config
	regionConfig := awsConfig.Copy()
	regionConfig.Region = region

	// Create EC2 and IAM service clients with region-specific config
	svc := ec2.NewFromConfig(regionConfig)
	iamSvc := iam.NewFromConfig(regionConfig)

	// Function to process pages of instances
	paginator := ec2.NewDescribeInstancesPaginator(svc, &ec2.DescribeInstancesInput{})

	for paginator.HasMorePages() {
		// Retrieve the next page
		result, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Warn("Failed to retrieve EC2 instances page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		// Loop through the reservations and instances
		for _, r := range result.Reservations {
			for _, inst := range r.Instances {
				// Convert AWS SDK instance to Fern instance
				fernInstance := convertAWSInstanceToFern(inst)

				instanceWithRole := &ec2fern.InstanceWithIamRole{
					Instance: fernInstance,
					Region:   &region,
				}

				if inst.IamInstanceProfile != nil {
					roles, err := getIAMRoles(ctx, iamSvc, *inst.IamInstanceProfile.Arn)
					if err != nil {
						log.Warn("Failed to get IAM roles for instance",
							svc1log.SafeParam("instanceId", aws.ToString(inst.InstanceId)),
							svc1log.SafeParam("region", region),
							svc1log.Stacktrace(err))
						errors = append(errors, err.Error())
					}
					instanceWithRole.IamRoles = roles
				}

				ec2Instances = append(ec2Instances, instanceWithRole)
			}
		}
	}

	if len(ec2Instances) > 0 {
		log.Info("Successfully enumerated EC2 instances",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("instanceCount", len(ec2Instances)))
		return &ec2fern.Ec2EnumerateResult{
			Instances: ec2Instances,
		}, errors, nil
	}
	log.Info("No EC2 instances found in region", svc1log.SafeParam("region", region))
	return nil, errors, nil
}

func EnumerateEc2(ctx context.Context, awsConfig aws.Config, config ec2fern.Ec2EnumerateConfig) *ec2fern.Ec2EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting EC2 enumeration", svc1log.SafeParam("regionsCount", len(config.Regions)))

	// Define the report structure at the top
	report := &ec2fern.Ec2EnumerateReport{
		Config: &config,
		Result: &ec2fern.Ec2EnumerateResult{},
	}

	allInstances := []*ec2fern.InstanceWithIamRole{}
	allErrors := []string{}

	for _, region := range config.Regions {
		r, regionErrors, err := enumerateEc2ForRegion(ctx, awsConfig, region)
		if err != nil {
			log.Error("Fatal error enumerating EC2 instances in region",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			allErrors = append(allErrors, fmt.Sprintf("Error in region %s: %s", region, err.Error()))
			continue
		}
		if r != nil && r.Instances != nil {
			allInstances = append(allInstances, r.Instances...)
		}
		if len(regionErrors) > 0 {
			allErrors = append(allErrors, regionErrors...)
		}
	}

	// Only add Result if there are EC2 instances found
	if len(allInstances) > 0 {
		report.Result = &ec2fern.Ec2EnumerateResult{
			Instances: allInstances,
		}
	}
	report.Errors = allErrors
	return report
}

// extractInstanceProfileName extracts the instance profile name from the ARN
func extractInstanceProfileName(profileArn string) string {
	parts := strings.Split(profileArn, "/")
	return parts[len(parts)-1]
}

// getIAMRoles retrieves the IAM roles associated with the the instance profile name
func getIAMRoles(ctx context.Context, iamSvc *iam.Client, instanceProfileArn string) ([]string, error) {
	log := svc1log.FromContext(ctx)
	instanceProfileName := extractInstanceProfileName(instanceProfileArn)
	log.Info("Getting IAM roles for instance profile",
		svc1log.SafeParam("instanceProfileName", instanceProfileName),
		svc1log.SafeParam("instanceProfileArn", instanceProfileArn))
	roles := []string{}

	input := &iam.GetInstanceProfileInput{
		InstanceProfileName: &instanceProfileName,
	}

	result, err := iamSvc.GetInstanceProfile(ctx, input)
	if err != nil {
		log.Warn("Failed to get instance profile",
			svc1log.SafeParam("instanceProfileName", instanceProfileName),
			svc1log.Stacktrace(err))
		return roles, err
	}

	for _, role := range result.InstanceProfile.Roles {
		roles = append(roles, *role.Arn)
	}

	if len(roles) == 0 {
		log.Warn("No roles found in instance profile",
			svc1log.SafeParam("instanceProfileName", instanceProfileName))
		return roles, fmt.Errorf("no roles found in instance profile - %s", instanceProfileName)
	}
	log.Info("Successfully retrieved IAM roles",
		svc1log.SafeParam("instanceProfileName", instanceProfileName),
		svc1log.SafeParam("roleCount", len(roles)))
	return roles, nil
}

// convertAWSInstanceToFern converts an AWS SDK EC2 Instance to a Fern EC2Instance
func convertAWSInstanceToFern(awsInstance ec2types.Instance) *ec2fern.Ec2Instance {
	fernInstance := &ec2fern.Ec2Instance{}

	// Convert basic string fields
	if awsInstance.InstanceId != nil {
		fernInstance.InstanceId = awsInstance.InstanceId
	}
	if awsInstance.ImageId != nil {
		fernInstance.ImageId = awsInstance.ImageId
	}
	if awsInstance.KeyName != nil {
		fernInstance.KeyName = awsInstance.KeyName
	}
	if awsInstance.PrivateIpAddress != nil {
		fernInstance.PrivateIpAddress = awsInstance.PrivateIpAddress
	}
	if awsInstance.PublicIpAddress != nil {
		fernInstance.PublicIpAddress = awsInstance.PublicIpAddress
	}
	if awsInstance.PrivateDnsName != nil {
		fernInstance.PrivateDnsName = awsInstance.PrivateDnsName
	}
	if awsInstance.PublicDnsName != nil {
		fernInstance.PublicDnsName = awsInstance.PublicDnsName
	}

	// Convert boolean fields
	if awsInstance.EbsOptimized != nil {
		fernInstance.EbsOptimized = awsInstance.EbsOptimized
	}

	// Convert time fields
	if awsInstance.LaunchTime != nil {
		fernInstance.LaunchTime = awsInstance.LaunchTime
	}

	// Convert enum fields
	if awsInstance.InstanceType != "" {
		instanceType := ec2fern.InstanceType(string(awsInstance.InstanceType))
		fernInstance.InstanceType = &instanceType
	}
	if awsInstance.Architecture != "" {
		architecture := ec2fern.Architecture(string(awsInstance.Architecture))
		fernInstance.Architecture = &architecture
	}
	if awsInstance.Hypervisor != "" {
		hypervisor := ec2fern.HypervisorType(string(awsInstance.Hypervisor))
		fernInstance.Hypervisor = &hypervisor
	}
	if awsInstance.Platform != "" {
		platform := ec2fern.PlatformValues(string(awsInstance.Platform))
		fernInstance.Platform = &platform
	}

	// Convert IAM Instance Profile
	if awsInstance.IamInstanceProfile != nil {
		fernInstance.IamInstanceProfile = &ec2fern.IamInstanceProfile{
			Arn: awsInstance.IamInstanceProfile.Arn,
			Id:  awsInstance.IamInstanceProfile.Id,
		}
	}

	// Convert Placement
	if awsInstance.Placement != nil {
		fernInstance.Placement = &ec2fern.Placement{
			AvailabilityZone: awsInstance.Placement.AvailabilityZone,
			Affinity:         awsInstance.Placement.Affinity,
			GroupName:        awsInstance.Placement.GroupName,
			HostId:           awsInstance.Placement.HostId,
			Tenancy:          (*string)(&awsInstance.Placement.Tenancy),
			SpreadDomain:     awsInstance.Placement.SpreadDomain,
			GroupId:          awsInstance.Placement.GroupId,
		}
		if awsInstance.Placement.PartitionNumber != nil {
			partitionNumber := int(*awsInstance.Placement.PartitionNumber)
			fernInstance.Placement.PartitionNumber = &partitionNumber
		}
		if awsInstance.Placement.HostResourceGroupArn != nil {
			fernInstance.Placement.HostResourceGroupArn = awsInstance.Placement.HostResourceGroupArn
		}
	}

	// Convert Network Interfaces
	if awsInstance.NetworkInterfaces != nil {
		var fernNetworkInterfaces []*ec2fern.InstanceNetworkInterface
		for _, ni := range awsInstance.NetworkInterfaces {
			fernNI := &ec2fern.InstanceNetworkInterface{
				NetworkInterfaceId: ni.NetworkInterfaceId,
				SubnetId:           ni.SubnetId,
				VpcId:              ni.VpcId,
				Description:        ni.Description,
				OwnerId:            ni.OwnerId,
				Status:             func() *string { s := string(ni.Status); return &s }(),
				MacAddress:         ni.MacAddress,
				PrivateIpAddress:   ni.PrivateIpAddress,
				PrivateDnsName:     ni.PrivateDnsName,
				SourceDestCheck:    ni.SourceDestCheck,
			}
			fernNetworkInterfaces = append(fernNetworkInterfaces, fernNI)
		}
		fernInstance.NetworkInterfaces = fernNetworkInterfaces
	}

	// Convert Tags
	if awsInstance.Tags != nil {
		var fernTags []*ec2fern.Tag
		for _, tag := range awsInstance.Tags {
			fernTag := &ec2fern.Tag{
				Key:   tag.Key,
				Value: tag.Value,
			}
			fernTags = append(fernTags, fernTag)
		}
		fernInstance.Tags = fernTags
	}

	return fernInstance
}
