package enumerate

import (
	"context"
	"strings"

	ec2fern "github.com/Method-Security/methodaws/generated/go/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// convertInstanceToFern converts AWS EC2 Instance to Fern Ec2Instance
func convertInstanceToFern(ctx context.Context, awsInstance types.Instance, region string) (*ec2fern.Ec2Instance, []string) {
	var errors []string

	// Convert instance state
	var state *ec2fern.InstanceState
	if awsInstance.State != nil {
		state = convertInstanceState(awsInstance.State.Name)
	}

	// Convert placement
	var placement *ec2fern.Placement
	if awsInstance.Placement != nil {
		placement = convertPlacement(awsInstance.Placement)
	}

	// Convert tags and extract name
	var tags []*ec2fern.Tag
	var name *string
	if len(awsInstance.Tags) > 0 {
		tags = convertTags(awsInstance.Tags)
		name = extractNameFromTags(awsInstance.Tags)
	}

	// Convert IAM instance profile
	var iamInstanceProfile *ec2fern.IamInstanceProfile
	if awsInstance.IamInstanceProfile != nil {
		iamInstanceProfile = convertIamInstanceProfile(awsInstance.IamInstanceProfile)
	}

	// Convert network interfaces
	var networkInterfaces []*ec2fern.InstanceNetworkInterface
	if len(awsInstance.NetworkInterfaces) > 0 {
		networkInterfaces, errors = convertNetworkInterfaces(ctx, awsInstance.NetworkInterfaces, region)
	}

	// Extract security group IDs
	var securityGroupIds []string
	if len(awsInstance.SecurityGroups) > 0 {
		securityGroupIds = extractSecurityGroupIds(awsInstance.SecurityGroups)
	}

	// Create instance with nested structure
	instance := &ec2fern.Ec2Instance{
		Identification: &ec2fern.Ec2InstanceIdentificationInfo{
			Id:     *awsInstance.InstanceId,
			Region: region,
			Name:   name,
		},
		Configuration: &ec2fern.Ec2InstanceConfigurationInfo{
			State:            state,
			ImageId:          awsInstance.ImageId,
			KeyName:          awsInstance.KeyName,
			InstanceType:     convertInstanceType(awsInstance.InstanceType),
			LaunchTime:       awsInstance.LaunchTime,
			Placement:        placement,
			PrivateIpAddress: awsInstance.PrivateIpAddress,
			PublicIpAddress:  awsInstance.PublicIpAddress,
			PrivateDnsName:   awsInstance.PrivateDnsName,
			PublicDnsName:    awsInstance.PublicDnsName,
			Architecture:     convertArchitecture(awsInstance.Architecture),
			Hypervisor:       convertHypervisor(awsInstance.Hypervisor),
			Platform:         convertPlatform(awsInstance.Platform),
			EbsOptimized:     awsInstance.EbsOptimized,
			Tags:             tags,
		},
		Resources: &ec2fern.Ec2InstanceResourceInfo{
			NetworkInterfaces:  networkInterfaces,
			IamInstanceProfile: iamInstanceProfile,
			SecurityGroupIds:   securityGroupIds,
		},
	}

	return instance, errors
}

// convertInstanceState converts AWS instance state to Fern enum
func convertInstanceState(state types.InstanceStateName) *ec2fern.InstanceState {
	stateStr := strings.ToUpper(string(state))
	fernState := ec2fern.InstanceState(stateStr)
	return &fernState
}

// convertInstanceType converts AWS instance type to Fern enum
func convertInstanceType(instanceType types.InstanceType) *ec2fern.InstanceType {
	if instanceType == "" {
		return nil
	}
	typeStr := strings.ToUpper(strings.ReplaceAll(string(instanceType), ".", "_"))
	fernType := ec2fern.InstanceType(typeStr)
	return &fernType
}

// convertArchitecture converts AWS architecture to Fern enum
func convertArchitecture(arch types.ArchitectureValues) *ec2fern.Architecture {
	if arch == "" {
		return nil
	}
	archStr := strings.ToUpper(strings.ReplaceAll(string(arch), "-", "_"))
	fernArch := ec2fern.Architecture(archStr)
	return &fernArch
}

// convertHypervisor converts AWS hypervisor to Fern enum
func convertHypervisor(hypervisor types.HypervisorType) *ec2fern.HypervisorType {
	if hypervisor == "" {
		return nil
	}
	hypervisorStr := strings.ToUpper(string(hypervisor))
	fernHypervisor := ec2fern.HypervisorType(hypervisorStr)
	return &fernHypervisor
}

// convertPlatform converts AWS platform to Fern enum
func convertPlatform(platform types.PlatformValues) *ec2fern.PlatformValues {
	if platform == "" {
		return nil
	}
	platformStr := strings.ToUpper(string(platform))
	fernPlatform := ec2fern.PlatformValues(platformStr)
	return &fernPlatform
}

// convertIamInstanceProfile converts AWS IAM instance profile to Fern format
func convertIamInstanceProfile(profile *types.IamInstanceProfile) *ec2fern.IamInstanceProfile {
	return &ec2fern.IamInstanceProfile{
		Id:  profile.Id,
		Arn: profile.Arn,
	}
}

// convertPlacement converts AWS placement to Fern format
func convertPlacement(placement *types.Placement) *ec2fern.Placement {
	fernPlacement := &ec2fern.Placement{
		AvailabilityZone: placement.AvailabilityZone,
		Affinity:         placement.Affinity,
		GroupName:        placement.GroupName,
		HostId:           placement.HostId,
		SpreadDomain:     placement.SpreadDomain,
		GroupId:          placement.GroupId,
	}

	if placement.Tenancy != "" {
		tenancy := string(placement.Tenancy)
		fernPlacement.Tenancy = &tenancy
	}

	if placement.PartitionNumber != nil {
		partitionNum := int(*placement.PartitionNumber)
		fernPlacement.PartitionNumber = &partitionNum
	}

	fernPlacement.HostResourceGroupArn = placement.HostResourceGroupArn

	return fernPlacement
}

// convertNetworkInterfaces converts AWS network interfaces to Fern format
func convertNetworkInterfaces(ctx context.Context, interfaces []types.InstanceNetworkInterface, region string) ([]*ec2fern.InstanceNetworkInterface, []string) {
	var fernInterfaces []*ec2fern.InstanceNetworkInterface
	var errors []string
	log := svc1log.FromContext(ctx)
	for _, ni := range interfaces {
		if ni.NetworkInterfaceId == nil {
			log.Warn("Network interface ID is nil for network interface", svc1log.SafeParam("networkInterface", ni))
			errors = append(errors, "Network interface ID is nil")
			continue
		}
		if ni.VpcId == nil {
			log.Warn("VPC ID is nil for network interface", svc1log.SafeParam("networkInterface", ni))
			errors = append(errors, "VPC ID is nil")
			continue
		}

		// Prepare status
		var status *string
		if ni.Status != "" {
			statusStr := string(ni.Status)
			status = &statusStr
		}

		// Prepare subnet IDs if available
		var subnetIds []string
		if ni.SubnetId != nil {
			subnetIds = []string{*ni.SubnetId}
		}

		// Create VPC instance
		vpcInstance := &ec2fern.VpcInstance{
			Id:        *ni.VpcId,
			SubnetIds: subnetIds,
		}

		// Create network interface with nested structure
		fernNI := &ec2fern.InstanceNetworkInterface{
			Identification: &ec2fern.InstanceNetworkInterfaceIdentificationInfo{
				Id:     *ni.NetworkInterfaceId,
				Arn:    ni.NetworkInterfaceId, // Using the ID as placeholder for ARN
				Region: region,
			},
			Configuration: &ec2fern.InstanceNetworkInterfaceConfigurationInfo{
				Description:      ni.Description,
				OwnerId:          ni.OwnerId,
				Status:           status,
				MacAddress:       ni.MacAddress,
				PrivateIpAddress: ni.PrivateIpAddress,
				PrivateDnsName:   ni.PrivateDnsName,
				SourceDestCheck:  ni.SourceDestCheck,
			},
			Resources: &ec2fern.InstanceNetworkInterfaceResourceInfo{
				Vpc: vpcInstance,
			},
		}

		fernInterfaces = append(fernInterfaces, fernNI)
	}

	return fernInterfaces, errors
}

// convertTags converts AWS tags to Fern format
func convertTags(tags []types.Tag) []*ec2fern.Tag {
	var fernTags []*ec2fern.Tag

	for _, tag := range tags {
		fernTag := &ec2fern.Tag{
			Key:   tag.Key,
			Value: tag.Value,
		}
		fernTags = append(fernTags, fernTag)
	}

	return fernTags
}

// extractNameFromTags extracts the name from EC2 tags
func extractNameFromTags(tags []types.Tag) *string {
	for _, tag := range tags {
		if tag.Key != nil && *tag.Key == "Name" && tag.Value != nil {
			return tag.Value
		}
	}
	return nil
}

// extractSecurityGroupIds extracts security group IDs from AWS security groups
func extractSecurityGroupIds(securityGroups []types.GroupIdentifier) []string {
	var securityGroupIds []string

	for _, sg := range securityGroups {
		if sg.GroupId != nil {
			securityGroupIds = append(securityGroupIds, *sg.GroupId)
		}
	}

	return securityGroupIds
}
