package eks

import (
	"context"
	"fmt"

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
		Name:     &nodeGroupName,
		NodeRole: nodeGroupDetail.Nodegroup.NodeRole,
	}

	// Get instances for the node group
	instances, errs := getInstancesForNodeGroup(ctx, cfg, clusterName, nodeGroupName)
	errors = append(errors, errs...)

	// Convert instances to Fern format
	var fernInstances []*eksfern.Ec2Instance
	for _, inst := range instances {
		if inst.InstanceId == nil {
			errors = append(errors, fmt.Sprintf("Instance ID is nil for instance %v", inst))
			continue
		}
		fernInstances = append(fernInstances, &eksfern.Ec2Instance{
			Id: *inst.InstanceId,
		})
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
		resources.ResourcesVpcConfig = convertVpcConfigToFern(cluster.ResourcesVpcConfig)
	}

	// Add Kubernetes network config to resources
	if cluster.KubernetesNetworkConfig != nil {
		resources.KubernetesNetworkConfig = convertKubernetesNetworkConfigToFern(cluster.KubernetesNetworkConfig)
	}

	// Add logging to resources
	if cluster.Logging != nil {
		resources.Logging = convertLoggingToFern(cluster.Logging)
	}

	// Add identity to resources
	if cluster.Identity != nil {
		resources.Identity = convertIdentityToFern(cluster.Identity)
	}

	// Add encryption config to resources
	if cluster.EncryptionConfig != nil {
		var encryptionConfigs []*eksfern.EksEncryptionConfig
		for _, config := range cluster.EncryptionConfig {
			encryptionConfigs = append(encryptionConfigs, convertEncryptionConfigToFern(&config))
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

	// Create EksInstance
	fernCluster := &eksfern.EksInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return fernCluster
}

// Helper conversion functions
func convertVpcConfigToFern(config *eksTypes.VpcConfigResponse) *eksfern.EksVpcConfig {
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

func convertLoggingToFern(logging *eksTypes.Logging) *eksfern.EksLogging {
	if logging == nil {
		return nil
	}

	fernLogging := &eksfern.EksLogging{}

	if logging.ClusterLogging != nil {
		var clusterLoggings []*eksfern.EksClusterLogging
		for _, cl := range logging.ClusterLogging {
			clusterLoggings = append(clusterLoggings, &eksfern.EksClusterLogging{
				Enabled: cl.Enabled,
				Types:   convertLogTypesToStrings(cl.Types),
			})
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

func convertEncryptionConfigToFern(config *eksTypes.EncryptionConfig) *eksfern.EksEncryptionConfig {
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
