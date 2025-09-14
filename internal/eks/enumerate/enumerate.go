package eks

import (
	"context"
	"fmt"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	ec2 "github.com/Method-Security/methodaws/generated/go/ec2"
	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	"github.com/aws/aws-sdk-go-v2/aws"
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
	_, errs := getNodeGroupsForCluster(ctx, cfg, eksSvc, clusterName)
	errors = append(errors, errs...)

	// Convert cluster to Fern format with new structure
	cluster := convertClusterToFern(clusterDetail.Cluster, region)

	return cluster, errors
}

// getNodeGroupsForCluster gets all node groups for a cluster (currently disabled)
func getNodeGroupsForCluster(ctx context.Context, cfg aws.Config, eksSvc *eks.Client, clusterName string) (interface{}, []string) {
	// NodeGroup type not available in generated code, returning nil
	return nil, nil
	/*
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
	*/
}

// convertClusterToFern converts AWS EKS cluster to Fern format with new structure
func convertClusterToFern(cluster *eksTypes.Cluster, region string) *eksfern.EksInstance {
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

	// Create resource info (only include supported fields)
	resources := &eksfern.EksResourceInfo{}

	// Note: The following fields are not currently supported in EksResourceInfo:
	// - NodeGroups, ResourcesVpcConfig, KubernetesNetworkConfig, Logging, Identity,
	//   EncryptionConfig, ConnectorConfig, Health, OutpostConfig

	// Discover and add AWS resource references
	discoverEksResourceReferences(cluster, nil, resources, region)

	// Create EksInstance
	fernCluster := &eksfern.EksInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return fernCluster
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
func createIamRoleReference(arn, region string) *common.IamRoleReference {
	if arn == "" {
		return nil
	}

	// Extract role name from ARN
	parts := strings.Split(arn, "/")
	var roleName string
	if len(parts) > 1 {
		roleName = parts[len(parts)-1]
	}

	return &common.IamRoleReference{
		Arn:      arn,
		RoleName: &roleName,
		Region:   region,
	}
}

// createVpcReference creates a VPC reference with subnet information
func createVpcReference(vpcID string, subnetIds []string, region string) *common.VpcReference {
	if vpcID == "" {
		return nil
	}

	return &common.VpcReference{
		Id:        vpcID,
		Region:    region,
		SubnetIds: subnetIds,
	}
}

// createSecurityGroupReference creates a security group reference
func createSecurityGroupReference(sgID, region string) *common.SecurityGroupReference {
	if sgID == "" {
		return nil
	}

	return &common.SecurityGroupReference{
		Id:     sgID,
		Region: region,
	}
}

// createKmsKeyReference creates a KMS key reference from an ARN
func createKmsKeyReference(keyArn, region string) *common.KmsKeyReference {
	if keyArn == "" {
		return nil
	}

	// Extract key ID from ARN
	parts := strings.Split(keyArn, "/")
	var keyID string
	if len(parts) > 1 {
		keyID = parts[len(parts)-1]
	} else {
		// If no "/" found, try to extract from colon-separated parts
		parts = strings.Split(keyArn, ":")
		if len(parts) > 0 {
			keyID = parts[len(parts)-1]
		}
	}

	return &common.KmsKeyReference{
		Arn:    keyArn,
		KeyId:  keyID,
		Region: region,
	}
}

// createCloudWatchLogReference creates a CloudWatch log reference from log group name
func createCloudWatchLogReference(logGroupName, region string) *common.CloudWatchLogReference {
	if logGroupName == "" {
		return nil
	}

	// Construct ARN for the log group
	arn := fmt.Sprintf("arn:aws:logs:%s::log-group:%s", region, logGroupName)

	return &common.CloudWatchLogReference{
		Arn:          arn,
		LogGroupName: logGroupName,
		Region:       region,
	}
}

// discoverEksResourceReferences discovers and sets AWS resource references for the EKS cluster
func discoverEksResourceReferences(cluster *eksTypes.Cluster, nodeGroups interface{}, resources *eksfern.EksResourceInfo, region string) {
	var iamRoles []*common.IamRoleReference
	var securityGroups []*common.SecurityGroupReference
	var ec2Instances []*ec2.Ec2Instance
	var kmsKeys []*common.KmsKeyReference
	var cloudWatchLogs []*common.CloudWatchLogReference

	// Track discovered resources to avoid duplicates
	discoveredRoles := make(map[string]bool)
	discoveredSGs := make(map[string]bool)
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

	// Note: NodeGroup resource discovery disabled (NodeGroup type not available)

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
