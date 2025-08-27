package securitygroup

import (
	// Standard
	"context"
	"fmt"

	// Generated
	fernsecuritygroup "github.com/Method-Security/methodaws/generated/go/securitygroup"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EnumerateSecurityGroups lists all of the security groups available to the caller across multiple regions
// alongside any non-fatal errors that occurred during the execution of the `methodaws securitygroup enumerate` subcommand.
// If vpcID is not nil, it will only return security groups associated with that VPC.
func EnumerateSecurityGroups(ctx context.Context, cfg aws.Config, config fernsecuritygroup.Ec2SecurityGroupsEnumerateConfig) *fernsecuritygroup.Ec2SecurityGroupsEnumerateReport {
	report := fernsecuritygroup.Ec2SecurityGroupsEnumerateReport{
		Config: &config,
		Result: &fernsecuritygroup.Ec2SecurityGroupsEnumerateResult{},
	}

	var allSecurityGroups []*fernsecuritygroup.SecurityGroup
	var allErrors []string

	for _, region := range config.Regions {
		securityGroups, errors := enumerateSecurityGroupForRegion(ctx, cfg, config.VpcId, region)
		// Convert AWS SDK SecurityGroups to Fern SecurityGroups
		for _, sg := range securityGroups {
			fernSG := convertAWSSecurityGroupToFern(sg, region)
			allSecurityGroups = append(allSecurityGroups, fernSG)
		}
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
			errors = append(errors, fmt.Sprintf("Error in region %s: %v", region, err))
			break
		}
		securityGroups = append(securityGroups, output.SecurityGroups...)
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
