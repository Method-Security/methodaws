package vpc

import (
	"context"
	"strings"

	vpcfern "github.com/Method-Security/methodaws/generated/go/vpc"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateVPC(ctx context.Context, awsConfig aws.Config, config vpcfern.VpcEnumerateConfig) *vpcfern.VpcEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting VPC enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &vpcfern.VpcEnumerateReport{
		Config: &config,
		Result: &vpcfern.VpcEnumerateResult{},
	}

	var allVPCs []*vpcfern.VpcInstance
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing VPCs and Subnets in region", svc1log.SafeParam("region", region))
		vpcs, errors := enumerateVPCWithSubnetsForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating VPCs/Subnets in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allVPCs = append(allVPCs, vpcs...)
		allErrors = append(allErrors, errors...)

		totalSubnets := 0
		for _, vpcInstance := range vpcs {
			if vpcInstance.Subnets != nil {
				totalSubnets += len(vpcInstance.Subnets)
			}
		}

		log.Info("Successfully processed VPCs and Subnets in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("vpcCount", len(vpcs)),
			svc1log.SafeParam("subnetCount", totalSubnets))
	}

	// Marshal report
	if len(allVPCs) > 0 {
		report.Result.Vpcs = allVPCs
	}
	report.Errors = allErrors
	return report
}

func enumerateVPCWithSubnetsForRegion(ctx context.Context, cfg aws.Config, region string) ([]*vpcfern.VpcInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	svc := ec2.NewFromConfig(regionCfg)

	var vpcs []*vpcfern.VpcInstance
	var errors []string

	// First, get all VPCs
	vpcPaginator := ec2.NewDescribeVpcsPaginator(svc, &ec2.DescribeVpcsInput{})
	vpcMap := make(map[string]*vpcfern.VpcInstance)

	for vpcPaginator.HasMorePages() {
		result, err := vpcPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve VPCs page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		for _, vpc := range result.Vpcs {
			if vpc.VpcId == nil {
				log.Warn("VPC ID is nil", svc1log.SafeParam("vpc", vpc))
				errors = append(errors, "VPC ID is nil")
				continue
			}
			vpcInstance, errs := convertAWSVPCToFern(vpc, region)
			if vpcInstance != nil {
				vpcs = append(vpcs, vpcInstance)
				vpcMap[vpcInstance.Id] = vpcInstance
			}
			errors = append(errors, errs...)
		}
	}

	// Then, get all subnets and associate them with VPCs
	subnetPaginator := ec2.NewDescribeSubnetsPaginator(svc, &ec2.DescribeSubnetsInput{})

	for subnetPaginator.HasMorePages() {
		result, err := subnetPaginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve Subnets page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		for _, subnet := range result.Subnets {
			// check if the subnet has an ID
			if subnet.SubnetId == nil {
				log.Warn("Subnet ID is nil", svc1log.SafeParam("subnet", subnet))
				errors = append(errors, "Subnet ID is nil")
				continue
			}

			// Convert the subnet to a Fern subnet
			subnetConverted, errs := convertAWSSubnetToFern(subnet, region)
			if subnetConverted != nil && subnet.VpcId != nil {
				// Find the VPC this subnet belongs to using the AWS subnet's VPC ID
				if vpcInstance, exists := vpcMap[*subnet.VpcId]; exists {
					if vpcInstance.Subnets == nil {
						vpcInstance.Subnets = []*vpcfern.Subnet{}
					}
					vpcInstance.Subnets = append(vpcInstance.Subnets, subnetConverted)
				}
			}
			errors = append(errors, errs...)
		}
	}

	return vpcs, errors
}

// convertAWSVPCToFern converts an AWS VPC to a Fern VPC
func convertAWSVPCToFern(awsVPC ec2types.Vpc, region string) (*vpcfern.VpcInstance, []string) {
	errors := []string{}
	if awsVPC.VpcId == nil {
		return nil, errors
	}

	// Convert AWS VPC tags to Fern tags
	var tags []*vpcfern.Tag
	for _, tag := range awsVPC.Tags {
		tags = append(tags, &vpcfern.Tag{
			Key:   aws.ToString(tag.Key),
			Value: aws.ToString(tag.Value),
		})
	}

	// Convert CIDR block associations
	var cidrAssociations []*vpcfern.VpcCidrBlockAssociation
	for _, assoc := range awsVPC.CidrBlockAssociationSet {
		var statePtr *vpcfern.VpcCidrBlockState
		if assoc.CidrBlockState != nil {
			if s, err := vpcfern.NewVpcCidrBlockStateFromString(strings.ToUpper(string(assoc.CidrBlockState.State))); err == nil {
				statePtr = &s
			} else {
				errors = append(errors, err.Error())
			}
		}
		cidrAssociations = append(cidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId:  assoc.AssociationId,
			CidrBlock:      assoc.CidrBlock,
			CidrBlockState: statePtr,
		})
	}

	// Convert IPv6 CIDR block associations
	var ipv6CidrAssociations []*vpcfern.VpcCidrBlockAssociation
	for _, assoc := range awsVPC.Ipv6CidrBlockAssociationSet {
		var statePtr *vpcfern.VpcCidrBlockState
		if assoc.Ipv6CidrBlockState != nil {
			if s, err := vpcfern.NewVpcCidrBlockStateFromString(strings.ToUpper(string(assoc.Ipv6CidrBlockState.State))); err == nil {
				statePtr = &s
			} else {
				errors = append(errors, err.Error())
			}
		}
		ipv6CidrAssociations = append(ipv6CidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId:  assoc.AssociationId,
			CidrBlock:      assoc.Ipv6CidrBlock,
			CidrBlockState: statePtr,
		})
	}

	// Convert instance tenancy
	var tenancy *vpcfern.Tenancy
	if awsVPC.InstanceTenancy != "" {
		if t, err := vpcfern.NewTenancyFromString(strings.ToUpper(string(awsVPC.InstanceTenancy))); err == nil {
			tenancy = &t
		} else {
			errors = append(errors, err.Error())
		}
	}

	// Convert VPC state
	var state *vpcfern.VpcState
	if awsVPC.State != "" {
		if s, err := vpcfern.NewVpcStateFromString(strings.ToUpper(string(awsVPC.State))); err == nil {
			state = &s
		} else {
			errors = append(errors, err.Error())
		}
	}

	cidrAssociations = append(cidrAssociations, ipv6CidrAssociations...)
	vpc := &vpcfern.VpcInstance{
		Id:                      *awsVPC.VpcId,
		Arn:                     nil, // AWS VPC doesn't provide ARN directly in DescribeVpcs response
		Region:                  region,
		CreationCidrBlock:       awsVPC.CidrBlock,
		CidrBlockAssociationSet: cidrAssociations,
		DhcpOptionsId:           awsVPC.DhcpOptionsId,
		InstanceTenancy:         tenancy,
		IsDefault:               awsVPC.IsDefault,
		OwnerId:                 awsVPC.OwnerId,
		State:                   state,
		Tags:                    tags,
		Subnets:                 []*vpcfern.Subnet{}, // Initialize empty subnets slice
	}

	return vpc, errors
}

// convertAWSSubnetToFern converts an AWS Subnet to a Fern Subnet
func convertAWSSubnetToFern(awsSubnet ec2types.Subnet, region string) (*vpcfern.Subnet, []string) {
	errors := []string{}
	// Convert AWS Subnet tags to Fern tags
	var tags []*vpcfern.Tag
	for _, tag := range awsSubnet.Tags {
		tags = append(tags, &vpcfern.Tag{
			Key:   aws.ToString(tag.Key),
			Value: aws.ToString(tag.Value),
		})
	}

	// Convert subnet state
	var state *vpcfern.SubnetState
	if awsSubnet.State != "" {
		if s, err := vpcfern.NewSubnetStateFromString(strings.ToUpper(string(awsSubnet.State))); err == nil {
			state = &s
		} else {
			errors = append(errors, err.Error())
		}
	}

	// Convert IPv6 CIDR block associations
	var ipv6CidrAssociations []*vpcfern.VpcCidrBlockAssociation
	for _, assoc := range awsSubnet.Ipv6CidrBlockAssociationSet {
		var statePtr *vpcfern.VpcCidrBlockState
		if assoc.Ipv6CidrBlockState != nil {
			if s, err := vpcfern.NewVpcCidrBlockStateFromString(strings.ToUpper(string(assoc.Ipv6CidrBlockState.State))); err == nil {
				statePtr = &s
			} else {
				errors = append(errors, err.Error())
			}
		}
		ipv6CidrAssociations = append(ipv6CidrAssociations, &vpcfern.VpcCidrBlockAssociation{
			AssociationId:  assoc.AssociationId,
			CidrBlock:      assoc.Ipv6CidrBlock,
			CidrBlockState: statePtr,
		})
	}

	// Convert available IP address count from *int32 to *int
	var availableIPCount *int
	if awsSubnet.AvailableIpAddressCount != nil {
		count := int(*awsSubnet.AvailableIpAddressCount)
		availableIPCount = &count
	}

	// Convert EnableLniAtDeviceIndex from *int32 to *int
	var enableLni *int
	if awsSubnet.EnableLniAtDeviceIndex != nil {
		lni := int(*awsSubnet.EnableLniAtDeviceIndex)
		enableLni = &lni
	}

	// Convert PrivateDnsNameOptionsOnLaunch from complex type to string
	var privateDNSOptions *string
	if awsSubnet.PrivateDnsNameOptionsOnLaunch != nil {
		// Convert the complex type to a simple string representation
		// You might want to serialize this properly based on your needs
		options := "enabled" // This is a placeholder - you may want to extract specific fields
		privateDNSOptions = &options
	}

	// Create AvailabilityZone object from AWS data
	var availabilityZone *vpcfern.AvailabilityZone
	if awsSubnet.AvailabilityZone != nil || awsSubnet.AvailabilityZoneId != nil {
		availabilityZone = &vpcfern.AvailabilityZone{
			ZoneName: awsSubnet.AvailabilityZone,
			ZoneId:   awsSubnet.AvailabilityZoneId,
		}
	}

	subnet := &vpcfern.Subnet{
		Id:                            *awsSubnet.SubnetId,
		Arn:                           awsSubnet.SubnetArn,
		Region:                        region,
		AvailabilityZone:              availabilityZone,
		AvailableIpAddressCount:       availableIPCount,
		CidrBlock:                     awsSubnet.CidrBlock,
		DefaultForAz:                  awsSubnet.DefaultForAz,
		EnableLniAtDeviceIndex:        enableLni,
		Ipv6Native:                    awsSubnet.Ipv6Native,
		MapCustomerOwnedIpOnLaunch:    awsSubnet.MapCustomerOwnedIpOnLaunch,
		MapPublicIpOnLaunch:           awsSubnet.MapPublicIpOnLaunch,
		OutpostArn:                    awsSubnet.OutpostArn,
		OwnerId:                       awsSubnet.OwnerId,
		State:                         state,
		Tags:                          tags,
		AssignIpv6AddressOnCreation:   awsSubnet.AssignIpv6AddressOnCreation,
		CustomerOwnedIpv4Pool:         awsSubnet.CustomerOwnedIpv4Pool,
		EnableDns64:                   awsSubnet.EnableDns64,
		Ipv6CidrBlockAssociationSet:   ipv6CidrAssociations,
		PrivateDnsNameOptionsOnLaunch: privateDNSOptions,
	}

	return subnet, errors
}
