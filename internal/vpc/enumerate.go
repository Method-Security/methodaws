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
		log.Info("Processing VPCs in region", svc1log.SafeParam("region", region))
		vpcs, errors := enumerateVPCForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating VPCs in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allVPCs = append(allVPCs, vpcs...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed VPCs in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("vpcCount", len(vpcs)))
	}

	// Marshal report
	if len(allVPCs) > 0 {
		report.Result.Vpcs = allVPCs
	}
	report.Errors = allErrors
	return report
}

func enumerateVPCForRegion(ctx context.Context, cfg aws.Config, region string) ([]*vpcfern.VpcInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	svc := ec2.NewFromConfig(regionCfg)
	paginator := ec2.NewDescribeVpcsPaginator(svc, &ec2.DescribeVpcsInput{})

	var vpcs []*vpcfern.VpcInstance
	var errors []string

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve VPCs page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, err.Error())
			break
		}

		for _, vpc := range result.Vpcs {
			vpcInstance, errs := convertAWSVPCToFern(vpc, region)
			vpcs = append(vpcs, vpcInstance)
			errors = append(errors, errs...)
		}
	}

	return vpcs, errors
}

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
	vpc := &vpcfern.Vpc{
		CreationCidrBlock:       awsVPC.CidrBlock,
		CidrBlockAssociationSet: cidrAssociations,
		DhcpOptionsId:           awsVPC.DhcpOptionsId,
		InstanceTenancy:         tenancy,
		IsDefault:               awsVPC.IsDefault,
		OwnerId:                 awsVPC.OwnerId,
		State:                   state,
		Tags:                    tags,
		Id:                      awsVPC.VpcId,
	}

	return &vpcfern.VpcInstance{
		Vpc:    vpc,
		Region: region,
	}, errors
}
