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
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateSecurityGroups lists all of the security groups available to the caller across multiple regions
// alongside any non-fatal errors that occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, config fernsecuritygroup.Ec2SecurityGroupsEnumerateConfig) *fernsecuritygroup.Ec2SecurityGroupsEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting SecurityGroup enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("vpcId", config.VpcId))

	report := fernsecuritygroup.Ec2SecurityGroupsEnumerateReport{
		Config: &config,
		Result: &fernsecuritygroup.Ec2SecurityGroupsEnumerateResult{},
	}

	var allSecurityGroups []*fernsecuritygroup.SecurityGroup
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing SecurityGroups in region", svc1log.SafeParam("region", region))
		securityGroups, errors := enumerateSecurityGroupForRegion(ctx, cfg, config.VpcId, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating SecurityGroups in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		// Convert AWS SDK SecurityGroups to Fern SecurityGroups
		for _, sg := range securityGroups {
			fernSG := convertAWSSecurityGroupToFern(sg, region)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}

		log.Info("Successfully processed SecurityGroups in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))

		allErrors = append(allErrors, errors...)
	}

	if len(allSecurityGroups) > 0 {
		report.Result.SecurityGroups = allSecurityGroups
	}
	report.Errors = allErrors
	return &report
}

// enumerateSecurityGroupForRegion lists all of the security groups available to the caller for a specific region.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func enumerateSecurityGroupForRegion(ctx context.Context, cfg aws.Config, vpcID *string, region string) ([]ec2types.SecurityGroup, []string) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating SecurityGroups for region",
		svc1log.SafeParam("region", region),
		svc1log.SafeParam("vpcId", vpcID))

	cfg.Region = region
	svc := ec2.NewFromConfig(cfg)
	var securityGroups []ec2types.SecurityGroup
	var errors []string
	var filters []ec2types.Filter

	if vpcID != nil {
		filters = append(filters, ec2types.Filter{
			Name:   aws.String("vpc-id"),
			Values: []string{*vpcID},
		})
	}

	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, &ec2.DescribeSecurityGroupsInput{Filters: filters})

	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve SecurityGroups page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
	}

	if len(securityGroups) > 0 {
		log.Info("Successfully enumerated SecurityGroups",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("securityGroupCount", len(securityGroups)))
	} else {
		log.Info("No SecurityGroups found in region", svc1log.SafeParam("region", region))
	}
	return securityGroups, errors
}

// convertAWSSecurityGroupToFern converts an AWS SDK SecurityGroup to a Fern SecurityGroup
func convertAWSSecurityGroupToFern(awsSG ec2types.SecurityGroup, region string) *fernsecuritygroup.SecurityGroup {
	fernSG := &fernsecuritygroup.SecurityGroup{
		Region:           region,
		Description:      awsSG.Description,
		GroupId:          awsSG.GroupId,
		GroupName:        awsSG.GroupName,
		OwnerId:          awsSG.OwnerId,
		SecurityGroupArn: awsSG.SecurityGroupArn,
		VpcId:            awsSG.VpcId,
	}

	// Convert IP Permissions (Ingress)
	if awsSG.IpPermissions != nil {
		var fernIPPermissions []*fernsecuritygroup.IpPermission
		for _, perm := range awsSG.IpPermissions {
			fernPerm := &fernsecuritygroup.IpPermission{
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
			fernIPPermissions = append(fernIPPermissions, fernPerm)
		}
		fernSG.IpPermissions = fernIPPermissions
	}

	// Convert IP Permissions Egress
	if awsSG.IpPermissionsEgress != nil {
		var fernIPPermissionsEgress []*fernsecuritygroup.IpPermission
		for _, perm := range awsSG.IpPermissionsEgress {
			fernPerm := &fernsecuritygroup.IpPermission{
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
			fernIPPermissionsEgress = append(fernIPPermissionsEgress, fernPerm)
		}
		fernSG.IpPermissionsEgress = fernIPPermissionsEgress
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
