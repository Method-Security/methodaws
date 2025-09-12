package eks

import (
	"context"
	"fmt"
	"strings"

	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	eksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateEks enumerates EKS clusters based on the provided configuration
func EnumerateEks(ctx context.Context, awsConfig aws.Config, config eksfern.EksEnumerateConfig) *eksfern.EksEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting EKS enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &eksfern.EksEnumerateReport{
		Result: &eksfern.EksEnumerateResult{
			EksClusters: []*eksfern.EksInstance{},
		},
		Config: &config,
	}

	var allClusters []*eksfern.EksInstance
	var allErrors []string

	// Process each region
	for _, region := range config.Regions {
		log.Info("Processing EKS clusters in region", svc1log.SafeParam("region", region))
		clusters, errors := enumerateEksForRegion(ctx, awsConfig, region)
		allClusters = append(allClusters, clusters...)
		allErrors = append(allErrors, errors...)
	}

	// Populate report
	if len(allClusters) > 0 {
		report.Result.EksClusters = allClusters
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed EKS enumeration",
		svc1log.SafeParam("totalClusters", len(allClusters)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// enumerateEksForRegion enumerates all EKS clusters in a specified region
func enumerateEksForRegion(ctx context.Context, cfg aws.Config, region string) ([]*eksfern.EksInstance, []string) {
	cfg.Region = region

	eksSvc := eks.NewFromConfig(cfg)
	var clusters []*eksfern.EksInstance
	var errors []string

	// List clusters
	clusterList, err := eksSvc.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error listing clusters in region %s: %s", region, err.Error()))
		return clusters, errors
	}

	// Process each cluster
	for _, clusterName := range clusterList.Clusters {
		cluster, errs := processCluster(ctx, cfg, eksSvc, clusterName, region)
		if cluster != nil {
			clusters = append(clusters, cluster)
		}
		errors = append(errors, errs...)
	}

	return clusters, errors
}

// processCluster processes a single EKS cluster and its node groups
func processCluster(ctx context.Context, cfg aws.Config, eksSvc *eks.Client, clusterName string, region string) (*eksfern.EksInstance, []string) {
	var errors []string
	log := svc1log.FromContext(ctx)

	// Describe cluster
	clusterDetail, err := eksSvc.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing cluster %s: %s", clusterName, err.Error()))
		return nil, errors
	}

	// Convert cluster to Fern format
	if clusterDetail.Cluster == nil {
		log.Warn("Cluster is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster is nil")
		return nil, errors
	}
	if clusterDetail.Cluster.Name == nil {
		log.Warn("Cluster name is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster name is nil")
		return nil, errors
	}
	if clusterDetail.Cluster.Arn == nil {
		log.Warn("Cluster ARN is nil for cluster", svc1log.SafeParam("clusterName", clusterName))
		errors = append(errors, "Cluster ARN is nil")
		return nil, errors
	}
	// Get node groups
	nodeGroups, errs := getNodeGroupsForCluster(ctx, cfg, eksSvc, clusterName)
	errors = append(errors, errs...)

	// Convert cluster to Fern format with new structure
	cluster := convertClusterToFern(clusterDetail.Cluster, region, nodeGroups)

	return cluster, errors
}

// getNodeGroupsForCluster gets all node groups for a cluster
func getNodeGroupsForCluster(ctx context.Context, cfg aws.Config, eksSvc *eks.Client, clusterName string) ([]*eksfern.NodeGroup, []string) {
	var nodeGroups []*eksfern.NodeGroup
	var errors []string

	// List node groups
	nodeGroupList, err := eksSvc.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: &clusterName})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error listing node groups for cluster %s: %s", clusterName, err.Error()))
		return nodeGroups, errors
	}

	// Process each node group
	for _, nodeGroupName := range nodeGroupList.Nodegroups {
		nodeGroup, errs := processNodeGroup(ctx, cfg, eksSvc, clusterName, nodeGroupName)
		if nodeGroup != nil {
			nodeGroups = append(nodeGroups, nodeGroup)
		}
		errors = append(errors, errs...)
	}

	return nodeGroups, errors
}

// processNodeGroup processes a single node group
func processNodeGroup(ctx context.Context, cfg aws.Config, eksSvc *eks.Client, clusterName, nodeGroupName string) (*eksfern.NodeGroup, []string) {
	var errors []string

	// Get region from config
	region := cfg.Region

	// Describe node group
	nodeGroupDetail, err := eksSvc.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
		ClusterName:   &clusterName,
		NodegroupName: &nodeGroupName,
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing node group %s: %s", nodeGroupName, err.Error()))
		return nil, errors
	}

	nodeGroup := &eksfern.NodeGroup{
		Name: &nodeGroupName,
	}

	// Add IAM role reference
	if nodeGroupDetail.Nodegroup.NodeRole != nil {
		nodeGroup.NodeRole = createIamRoleReference(*nodeGroupDetail.Nodegroup.NodeRole, region)
	}

	// Get instances for the node group
	instances, errs := getInstancesForNodeGroup(ctx, cfg, clusterName, nodeGroupName)
	errors = append(errors, errs...)

	// Convert instances to Fern reference format
	var fernInstances []*eksfern.Ec2InstanceReference
	for _, inst := range instances {
		if inst.InstanceId == nil {
			errors = append(errors, fmt.Sprintf("Instance ID is nil for instance %v", inst))
			continue
		}
		fernInstances = append(fernInstances, createEc2InstanceReference(inst, region))
	}
	nodeGroup.Instances = fernInstances

	return nodeGroup, errors
}

// getInstancesForNodeGroup gets all instances for a node group
func getInstancesForNodeGroup(ctx context.Context, cfg aws.Config, clusterName, nodeGroupName string) ([]ec2types.Instance, []string) {
	var errors []string

	eksSvc := eks.NewFromConfig(cfg)
	asSvc := autoscaling.NewFromConfig(cfg)
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe the node group to get the associated ASG name
	nodeGroupOutput, err := eksSvc.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
		ClusterName:   &clusterName,
		NodegroupName: &nodeGroupName,
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing node group %s for instances: %s", nodeGroupName, err.Error()))
		return nil, errors
	}

	// Get the name of the ASG from the node group description
	var asgName string
	for _, asg := range nodeGroupOutput.Nodegroup.Resources.AutoScalingGroups {
		asgName = *asg.Name
		break // Assuming one ASG per node group, which is typical
	}

	if asgName == "" {
		errors = append(errors, fmt.Sprintf("No auto scaling group found for node group %s", nodeGroupName))
		return nil, errors
	}

	// Describe ASG to get the instance IDs
	asgDesc, err := asSvc.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{asgName},
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing ASG %s: %s", asgName, err.Error()))
		return nil, errors
	}

	var instanceIDs []string
	for _, group := range asgDesc.AutoScalingGroups {
		for _, instance := range group.Instances {
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}
	}

	if len(instanceIDs) == 0 {
		return nil, errors
	}

	// Describe EC2 instances by their IDs
	ec2Desc, err := ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	})
	if err != nil {
		errors = append(errors, fmt.Sprintf("Error describing instances: %s", err.Error()))
		return nil, errors
	}

	var instances []ec2types.Instance
	for _, reservation := range ec2Desc.Reservations {
		instances = append(instances, reservation.Instances...)
	}

	return instances, errors
}

// convertClusterToFern converts AWS EKS cluster to Fern format with new structure
func convertClusterToFern(cluster *eksTypes.Cluster, region string, nodeGroups []*eksfern.NodeGroup) *eksfern.EksInstance {
	if cluster == nil || cluster.Arn == nil || cluster.Name == nil {
		return nil
	}

	// Create identification info
	identification := &eksfern.EksIdentificationInfo{
		Arn:    *cluster.Arn,
		Name:   *cluster.Name,
		Id:     cluster.Id,
		Region: region,
	}

	// Create configuration info
	configuration := &eksfern.EksConfigurationInfo{
		Status:          eksfern.ClusterStatus(string(cluster.Status)),
		Endpoint:        cluster.Endpoint,
		Version:         cluster.Version,
		PlatformVersion: cluster.PlatformVersion,
		CreatedAt:       cluster.CreatedAt,
		RoleArn:         cluster.RoleArn,
	}

	// Add service role reference
	if cluster.RoleArn != nil {
		configuration.ServiceRole = createIamRoleReference(*cluster.RoleArn, region)
	}

	// Add tags to configuration
	if cluster.Tags != nil {
		configuration.Tags = cluster.Tags
	}

	// Add access config to configuration
	if cluster.AccessConfig != nil {
		configuration.AccessConfig = convertAccessConfigToFern(cluster.AccessConfig)
	}

	// Create resource info
	resources := &eksfern.EksResourceInfo{
		NodeGroups: nodeGroups,
	}

	// Add VPC config to resources
	if cluster.ResourcesVpcConfig != nil {
		resources.ResourcesVpcConfig = convertVpcConfigToFern(cluster.ResourcesVpcConfig, region)
	}

	// Add Kubernetes network config to resources
	if cluster.KubernetesNetworkConfig != nil {
		resources.KubernetesNetworkConfig = convertKubernetesNetworkConfigToFern(cluster.KubernetesNetworkConfig)
	}

	// Add logging to resources
	if cluster.Logging != nil {
		resources.Logging = convertLoggingToFern(cluster.Logging, *cluster.Name, region)
	}

	// Add identity to resources
	if cluster.Identity != nil {
		resources.Identity = convertIdentityToFern(cluster.Identity)
	}

	// Add encryption config to resources
	if cluster.EncryptionConfig != nil {
		var encryptionConfigs []*eksfern.EksEncryptionConfig
		for _, config := range cluster.EncryptionConfig {
			encryptionConfigs = append(encryptionConfigs, convertEncryptionConfigToFern(&config, region))
		}
		resources.EncryptionConfig = encryptionConfigs
	}

	// Add connector config to resources
	if cluster.ConnectorConfig != nil {
		resources.ConnectorConfig = convertConnectorConfigToFern(cluster.ConnectorConfig)
	}

	// Add health to resources
	if cluster.Health != nil {
		resources.Health = convertClusterHealthToFern(cluster.Health)
	}

	// Add outpost config to resources
	if cluster.OutpostConfig != nil {
		resources.OutpostConfig = convertOutpostConfigToFern(cluster.OutpostConfig)
	}

	// Discover and add AWS resource references
	discoverEksResourceReferences(cluster, nodeGroups, resources, region)

	// Create EksInstance
	fernCluster := &eksfern.EksInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return fernCluster
}

// Helper conversion functions
func convertVpcConfigToFern(config *eksTypes.VpcConfigResponse, region string) *eksfern.EksVpcConfig {
	if config == nil {
		return nil
	}

	vpcConfig := &eksfern.EksVpcConfig{
		ClusterSecurityGroupId: config.ClusterSecurityGroupId,
		PublicAccessCidrs:      config.PublicAccessCidrs,
		SecurityGroupIds:       config.SecurityGroupIds,
		SubnetIds:              config.SubnetIds,
		VpcId:                  config.VpcId,
	}

	// Add VPC reference
	if config.VpcId != nil {
		vpcConfig.Vpc = createVpcReference(*config.VpcId, config.SubnetIds, region)
	}

	// Add security group references
	var securityGroups []*eksfern.SecurityGroupReference
	for _, sgID := range config.SecurityGroupIds {
		sgRef := createSecurityGroupReference(sgID, region)
		if sgRef != nil {
			securityGroups = append(securityGroups, sgRef)
		}
	}
	if len(securityGroups) > 0 {
		vpcConfig.SecurityGroups = securityGroups
	}

	// EndpointConfigResponse access via individual fields
	vpcConfig.EndpointConfigResponse = &eksfern.EksEndpointConfigResponse{
		PrivateAccess: &config.EndpointPrivateAccess,
		PublicAccess:  &config.EndpointPublicAccess,
	}

	return vpcConfig
}

func convertKubernetesNetworkConfigToFern(config *eksTypes.KubernetesNetworkConfigResponse) *eksfern.EksKubernetesNetworkConfig {
	if config == nil {
		return nil
	}

	return &eksfern.EksKubernetesNetworkConfig{
		IpFamily:        (*string)(&config.IpFamily),
		ServiceIpv4Cidr: config.ServiceIpv4Cidr,
		ServiceIpv6Cidr: config.ServiceIpv6Cidr,
	}
}

func convertLoggingToFern(logging *eksTypes.Logging, clusterName, region string) *eksfern.EksLogging {
	if logging == nil {
		return nil
	}

	fernLogging := &eksfern.EksLogging{}

	if logging.ClusterLogging != nil {
		var clusterLoggings []*eksfern.EksClusterLogging
		for _, cl := range logging.ClusterLogging {
			clusterLogging := &eksfern.EksClusterLogging{
				Enabled: cl.Enabled,
				Types:   convertLogTypesToStrings(cl.Types),
			}

			// Add CloudWatch log reference if logging is enabled
			if cl.Enabled != nil && *cl.Enabled {
				logGroupName := fmt.Sprintf("/aws/eks/%s/cluster", clusterName)
				clusterLogging.CloudWatchLog = createCloudWatchLogReference(logGroupName, region)
			}

			clusterLoggings = append(clusterLoggings, clusterLogging)
		}
		fernLogging.ClusterLogging = clusterLoggings
	}

	return fernLogging
}

func convertLogTypesToStrings(types []eksTypes.LogType) []string {
	var stringTypes []string
	for _, t := range types {
		stringTypes = append(stringTypes, string(t))
	}
	return stringTypes
}

func convertIdentityToFern(identity *eksTypes.Identity) *eksfern.EksIdentity {
	if identity == nil {
		return nil
	}

	fernIdentity := &eksfern.EksIdentity{}

	if identity.Oidc != nil {
		fernIdentity.Oidc = &eksfern.EksOidc{
			Issuer: identity.Oidc.Issuer,
		}
	}

	return fernIdentity
}

func convertEncryptionConfigToFern(config *eksTypes.EncryptionConfig, region string) *eksfern.EksEncryptionConfig {
	if config == nil {
		return nil
	}

	fernConfig := &eksfern.EksEncryptionConfig{
		Resources: config.Resources,
	}

	if config.Provider != nil {
		fernConfig.Provider = &eksfern.EksProvider{
			KeyArn: config.Provider.KeyArn,
		}

		// Add KMS key reference
		if config.Provider.KeyArn != nil {
			fernConfig.Provider.KmsKey = createKmsKeyReference(*config.Provider.KeyArn, region)
		}
	}

	return fernConfig
}

func convertConnectorConfigToFern(config *eksTypes.ConnectorConfigResponse) *eksfern.EksConnectorConfig {
	if config == nil {
		return nil
	}

	return &eksfern.EksConnectorConfig{
		ActivationCode:   config.ActivationCode,
		ActivationExpiry: config.ActivationExpiry,
		ActivationId:     config.ActivationId,
		Provider:         config.Provider,
		RoleArn:          config.RoleArn,
	}
}

func convertClusterHealthToFern(health *eksTypes.ClusterHealth) *eksfern.EksClusterHealth {
	if health == nil {
		return nil
	}

	fernHealth := &eksfern.EksClusterHealth{}

	if health.Issues != nil {
		var issues []*eksfern.EksClusterIssue
		for _, issue := range health.Issues {
			issues = append(issues, &eksfern.EksClusterIssue{
				Code:        (*string)(&issue.Code),
				Message:     issue.Message,
				ResourceIds: issue.ResourceIds,
			})
		}
		fernHealth.Issues = issues
	}

	return fernHealth
}

func convertOutpostConfigToFern(config *eksTypes.OutpostConfigResponse) *eksfern.EksOutpostConfig {
	if config == nil {
		return nil
	}

	fernConfig := &eksfern.EksOutpostConfig{
		ControlPlaneInstanceType: config.ControlPlaneInstanceType,
		OutpostArns:              config.OutpostArns,
	}

	if config.ControlPlanePlacement != nil {
		fernConfig.ControlPlanePlacement = &eksfern.EksControlPlanePlacement{
			GroupName: config.ControlPlanePlacement.GroupName,
		}
	}

	return fernConfig
}

func convertAccessConfigToFern(config *eksTypes.AccessConfigResponse) *eksfern.EksAccessConfig {
	if config == nil {
		return nil
	}

	return &eksfern.EksAccessConfig{
		AuthenticationMode:                      (*string)(&config.AuthenticationMode),
		BootstrapClusterCreatorAdminPermissions: config.BootstrapClusterCreatorAdminPermissions,
	}
}

// AWS Resource Reference Helper Functions

// createIamRoleReference creates an IAM role reference from an ARN
func createIamRoleReference(arn, region string) *eksfern.IamRoleReference {
	if arn == "" {
		return nil
	}

	// Extract role name from ARN
	parts := strings.Split(arn, "/")
	var roleName string
	if len(parts) > 1 {
		roleName = parts[len(parts)-1]
	}

	return &eksfern.IamRoleReference{
		Arn:      arn,
		RoleName: roleName,
		Region:   region,
	}
}

// createVpcReference creates a VPC reference with subnet information
func createVpcReference(vpcId string, subnetIds []string, region string) *eksfern.VpcReference {
	if vpcId == "" {
		return nil
	}

	return &eksfern.VpcReference{
		Id:        vpcId,
		Region:    region,
		SubnetIds: subnetIds,
	}
}

// createSecurityGroupReference creates a security group reference
func createSecurityGroupReference(sgID, region string) *eksfern.SecurityGroupReference {
	if sgID == "" {
		return nil
	}

	return &eksfern.SecurityGroupReference{
		Id:     sgID,
		Region: region,
	}
}

// createEc2InstanceReference creates an EC2 instance reference
func createEc2InstanceReference(instance ec2types.Instance, region string) *eksfern.Ec2InstanceReference {
	if instance.InstanceId == nil {
		return nil
	}

	var instanceType, availabilityZone string
	if instance.InstanceType != "" {
		instanceType = string(instance.InstanceType)
	}
	if instance.Placement != nil && instance.Placement.AvailabilityZone != nil {
		availabilityZone = *instance.Placement.AvailabilityZone
	}

	return &eksfern.Ec2InstanceReference{
		Id:               *instance.InstanceId,
		Region:           region,
		InstanceType:     &instanceType,
		AvailabilityZone: &availabilityZone,
	}
}

// createKmsKeyReference creates a KMS key reference from an ARN
func createKmsKeyReference(keyArn, region string) *eksfern.KmsKeyReference {
	if keyArn == "" {
		return nil
	}

	// Extract key ID from ARN
	parts := strings.Split(keyArn, "/")
	var keyId string
	if len(parts) > 1 {
		keyId = parts[len(parts)-1]
	} else {
		// If no "/" found, try to extract from colon-separated parts
		parts = strings.Split(keyArn, ":")
		if len(parts) > 0 {
			keyId = parts[len(parts)-1]
		}
	}

	return &eksfern.KmsKeyReference{
		Arn:    keyArn,
		KeyId:  keyId,
		Region: region,
	}
}

// createCloudWatchLogReference creates a CloudWatch log reference from log group name
func createCloudWatchLogReference(logGroupName, region string) *eksfern.CloudWatchLogReference {
	if logGroupName == "" {
		return nil
	}

	// Construct ARN for the log group
	arn := fmt.Sprintf("arn:aws:logs:%s::log-group:%s", region, logGroupName)

	return &eksfern.CloudWatchLogReference{
		Arn:          arn,
		LogGroupName: logGroupName,
		Region:       region,
	}
}

// discoverEksResourceReferences discovers and sets AWS resource references for the EKS cluster
func discoverEksResourceReferences(cluster *eksTypes.Cluster, nodeGroups []*eksfern.NodeGroup, resources *eksfern.EksResourceInfo, region string) {
	var iamRoles []*eksfern.IamRoleReference
	var securityGroups []*eksfern.SecurityGroupReference
	var ec2Instances []*eksfern.Ec2InstanceReference
	var kmsKeys []*eksfern.KmsKeyReference
	var cloudWatchLogs []*eksfern.CloudWatchLogReference

	// Track discovered resources to avoid duplicates
	discoveredRoles := make(map[string]bool)
	discoveredSGs := make(map[string]bool)
	discoveredInstances := make(map[string]bool)
	discoveredKeys := make(map[string]bool)
	discoveredLogs := make(map[string]bool)

	// Discover IAM role from cluster service role
	if cluster.RoleArn != nil {
		roleRef := createIamRoleReference(*cluster.RoleArn, region)
		if roleRef != nil && !discoveredRoles[roleRef.Arn] {
			iamRoles = append(iamRoles, roleRef)
			discoveredRoles[roleRef.Arn] = true
		}
	}

	// Discover VPC and security groups from VPC config
	if cluster.ResourcesVpcConfig != nil {
		// Set VPC reference
		if cluster.ResourcesVpcConfig.VpcId != nil {
			vpcRef := createVpcReference(*cluster.ResourcesVpcConfig.VpcId, cluster.ResourcesVpcConfig.SubnetIds, region)
			if vpcRef != nil {
				resources.Vpc = vpcRef
			}
		}

		// Discover security groups
		for _, sgID := range cluster.ResourcesVpcConfig.SecurityGroupIds {
			if !discoveredSGs[sgID] {
				sgRef := createSecurityGroupReference(sgID, region)
				if sgRef != nil {
					securityGroups = append(securityGroups, sgRef)
					discoveredSGs[sgID] = true
				}
			}
		}

		// Add cluster security group if present
		if cluster.ResourcesVpcConfig.ClusterSecurityGroupId != nil {
			sgID := *cluster.ResourcesVpcConfig.ClusterSecurityGroupId
			if !discoveredSGs[sgID] {
				sgRef := createSecurityGroupReference(sgID, region)
				if sgRef != nil {
					securityGroups = append(securityGroups, sgRef)
					discoveredSGs[sgID] = true
				}
			}
		}
	}

	// Discover KMS keys from encryption config
	if cluster.EncryptionConfig != nil {
		for _, encryptionCfg := range cluster.EncryptionConfig {
			if encryptionCfg.Provider != nil && encryptionCfg.Provider.KeyArn != nil {
				keyRef := createKmsKeyReference(*encryptionCfg.Provider.KeyArn, region)
				if keyRef != nil && !discoveredKeys[keyRef.Arn] {
					kmsKeys = append(kmsKeys, keyRef)
					discoveredKeys[keyRef.Arn] = true
				}
			}
		}
	}

	// Discover CloudWatch logs from logging config
	if cluster.Logging != nil && cluster.Logging.ClusterLogging != nil {
		for _, logConfig := range cluster.Logging.ClusterLogging {
			if logConfig.Enabled != nil && *logConfig.Enabled {
				// Construct log group name for EKS cluster
				logGroupName := fmt.Sprintf("/aws/eks/%s/cluster", *cluster.Name)
				if !discoveredLogs[logGroupName] {
					logRef := createCloudWatchLogReference(logGroupName, region)
					if logRef != nil {
						cloudWatchLogs = append(cloudWatchLogs, logRef)
						discoveredLogs[logGroupName] = true
					}
				}
			}
		}
	}

	// Discover resources from node groups
	for _, nodeGroup := range nodeGroups {
		// Discover IAM role from node group
		if nodeGroup.NodeRole != nil {
			if !discoveredRoles[nodeGroup.NodeRole.Arn] {
				iamRoles = append(iamRoles, nodeGroup.NodeRole)
				discoveredRoles[nodeGroup.NodeRole.Arn] = true
			}
		}

		// Discover EC2 instances from node group
		if nodeGroup.Instances != nil {
			for _, instance := range nodeGroup.Instances {
				if !discoveredInstances[instance.Id] {
					ec2Instances = append(ec2Instances, instance)
					discoveredInstances[instance.Id] = true
				}
			}
		}
	}

	// Set discovered resources
	if len(iamRoles) > 0 {
		resources.IamRoles = iamRoles
	}
	if len(securityGroups) > 0 {
		resources.SecurityGroups = securityGroups
	}
	if len(ec2Instances) > 0 {
		resources.Ec2Instances = ec2Instances
	}
	if len(kmsKeys) > 0 {
		resources.KmsKeys = kmsKeys
	}
	if len(cloudWatchLogs) > 0 {
		resources.CloudWatchLogs = cloudWatchLogs
	}
}
