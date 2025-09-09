package securitygroup

import (
	// Standard
	"context"
	"fmt"

	// Generated
	fernsecuritygroup "github.com/Method-Security/methodaws/generated/go/securitygroup"
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateSecurityGroups lists all of the security groups available to the caller across multiple regions
// alongside any non-fatal errors that occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// This includes both EC2/VPC security groups and RDS DB security groups.
// If vpcID is not nil, it will only return EC2 security groups associated with that VPC.
func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, config fernsecuritygroup.SecurityGroupsEnumerateConfig) *fernsecuritygroup.SecurityGroupsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting SecurityGroup enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)))

	report := fernsecuritygroup.SecurityGroupsEnumerateReport{
		Config: &config,
		Result: &fernsecuritygroup.SecurityGroupsEnumerateResult{},
	}

	var allSecurityGroups []*fernsecuritygroup.SecurityGroup
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing SecurityGroups in region", svc1log.SafeParam("region", region))

		// Enumerate EC2 security groups
		ec2SecurityGroups, ec2Errors := enumerateEC2SecurityGroupForRegion(ctx, cfg, region)

		// Enumerate RDS DB security groups
		rdsSecurityGroups, rdsErrors := enumerateRDSSecurityGroupForRegion(ctx, cfg, region)

		totalErrors := append(ec2Errors, rdsErrors...)
		if len(totalErrors) > 0 {
			log.Warn("Errors occurred while enumerating SecurityGroups in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(totalErrors)))
		}

		// Convert AWS SDK EC2 SecurityGroups to Fern SecurityGroups
		for _, sg := range ec2SecurityGroups {
			if sg.GroupId == nil {
				log.Warn("EC2 SecurityGroup ID is nil", svc1log.SafeParam("sg", sg))
				allErrors = append(allErrors, "EC2 SecurityGroup ID is nil")
				continue
			}
			fernSG := convertAWSEC2SecurityGroupToFern(sg, region)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}

		// Convert AWS SDK RDS DB SecurityGroups to Fern SecurityGroups
		for _, sg := range rdsSecurityGroups {
			if sg.DBSecurityGroupName == nil {
				log.Warn("RDS DB SecurityGroup Name is nil", svc1log.SafeParam("sg", sg))
				allErrors = append(allErrors, "RDS DB SecurityGroup Name is nil")
				continue
			}
			fernSG := convertAWSRDSSecurityGroupToFern(sg, region)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}

		log.Info("Successfully processed SecurityGroups in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("ec2SecurityGroupCount", len(ec2SecurityGroups)),
			svc1log.SafeParam("rdsSecurityGroupCount", len(rdsSecurityGroups)))

		allErrors = append(allErrors, totalErrors...)
	}

	if len(allSecurityGroups) > 0 {
		report.Result.SecurityGroups = allSecurityGroups
	}
	report.Errors = allErrors
	return &report
}

// enumerateEC2SecurityGroupForRegion lists all of the EC2 security groups available to the caller for a specific region.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func enumerateEC2SecurityGroupForRegion(ctx context.Context, cfg aws.Config, region string) ([]ec2types.SecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating EC2 SecurityGroups for region",
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("vpcId", nil))

	cfg.Region = region
	svc := ec2.NewFromConfig(cfg)
	var securityGroups []ec2types.SecurityGroup
	var errors []string

	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve EC2 SecurityGroups page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}

	if len(securityGroups) > 0 {
		log.Info("Successfully enumerated EC2 SecurityGroups",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))
	} else {
		log.Info("No EC2 SecurityGroups found in region", svc1log.SafeParam("region", region))
	}
	return securityGroups, errors
}

// enumerateRDSSecurityGroupForRegion lists all of the RDS DB security groups available to the caller for a specific region.
// Note: RDS DB security groups are mostly legacy for EC2-Classic which was retired August 15, 2022.
func enumerateRDSSecurityGroupForRegion(ctx context.Context, cfg aws.Config, region string) ([]rdstypes.DBSecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating RDS DB SecurityGroups for region",
		svc1log.SafeParam("region", region))

	cfg.Region = region
	svc := rds.NewFromConfig(cfg)
	var securityGroups []rdstypes.DBSecurityGroup
	var errors []string

	paginator := rds.NewDescribeDBSecurityGroupsPaginator(svc, &rds.DescribeDBSecurityGroupsInput{})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve RDS DB SecurityGroups page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.DBSecurityGroups...)
	}

	if len(securityGroups) > 0 {
		log.Info("Successfully enumerated RDS DB SecurityGroups",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))
	} else {
		log.Info("No RDS DB SecurityGroups found in region", svc1log.SafeParam("region", region))
	}
	return securityGroups, errors
}

// convertAWSEC2SecurityGroupToFern converts an AWS SDK EC2 SecurityGroup to a Fern SecurityGroup
func convertAWSEC2SecurityGroupToFern(awsSG ec2types.SecurityGroup, region string) *fernsecuritygroup.SecurityGroup {
	fernSG := &fernsecuritygroup.SecurityGroup{
		Id:                *awsSG.GroupId,
		Name:              awsSG.GroupName,
		Region:            region,
		SecurityGroupType: fernsecuritygroup.SecurityGroupTypeEc2,
		Description:       awsSG.Description,
		OwnerId:           awsSG.OwnerId,
		VpcId:             awsSG.VpcId,
	}

	// Convert IP Permissions (combining Ingress and Egress)
	var fernPermissions []*fernsecuritygroup.IpPermission

	// Add Ingress permissions
	if awsSG.IpPermissions != nil {
		for _, perm := range awsSG.IpPermissions {
			fernPerm := &fernsecuritygroup.IpPermission{
				Direction:  fernsecuritygroup.PermissionDirectionIngress,
				IpProtocol: perm.IpProtocol,
			}
			if perm.FromPort != nil {
				fromPort := int(*perm.FromPort)
				fernPerm.FromPort = &fromPort
			}
			if perm.ToPort != nil {
				toPort := int(*perm.ToPort)
				fernPerm.ToPort = &toPort
			}
			fernPermissions = append(fernPermissions, fernPerm)
		}
	}

	// Add Egress permissions
	if awsSG.IpPermissionsEgress != nil {
		for _, perm := range awsSG.IpPermissionsEgress {
			fernPerm := &fernsecuritygroup.IpPermission{
				Direction:  fernsecuritygroup.PermissionDirectionEgress,
				IpProtocol: perm.IpProtocol,
			}
			if perm.FromPort != nil {
				fromPort := int(*perm.FromPort)
				fernPerm.FromPort = &fromPort
			}
			if perm.ToPort != nil {
				toPort := int(*perm.ToPort)
				fernPerm.ToPort = &toPort
			}
			fernPermissions = append(fernPermissions, fernPerm)
		}
	}

	if len(fernPermissions) > 0 {
		fernSG.Permissions = fernPermissions
	}

	// Convert Tags
	if awsSG.Tags != nil {
		var fernTags []*fernsecuritygroup.Tag
		for _, tag := range awsSG.Tags {
			fernTag := &fernsecuritygroup.Tag{
				Key:   *tag.Key,
				Value: *tag.Value,
			}
			fernTags = append(fernTags, fernTag)
		}
		fernSG.Tags = fernTags
	}

	return fernSG
}

// convertAWSRDSSecurityGroupToFern converts an AWS SDK RDS DB SecurityGroup to a Fern SecurityGroup
func convertAWSRDSSecurityGroupToFern(awsSG rdstypes.DBSecurityGroup, region string) *fernsecuritygroup.SecurityGroup {
	fernSG := &fernsecuritygroup.SecurityGroup{
		Id:                *awsSG.DBSecurityGroupName,
		Arn:               awsSG.DBSecurityGroupArn,
		Region:            region,
		SecurityGroupType: fernsecuritygroup.SecurityGroupTypeRds,
		Description:       awsSG.DBSecurityGroupDescription,
		OwnerId:           awsSG.OwnerId,
		VpcId:             awsSG.VpcId,
	}
	// Note: EC2SecurityGroups and IPRanges are not included in the Fern SecurityGroup definition
	// These fields exist in the RDS DB SecurityGroup but are not mapped to the unified SecurityGroup schema

	return fernSG
}
