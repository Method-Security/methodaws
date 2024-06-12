package eks

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	eksTypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
)

type EC2Instance struct {
	InstanceID string `json:"instance_id" yaml:"instance_id"`
}

type NodeGroup struct {
	Name      string        `json:"name" yaml:"name"`
	NodeRole  string        `json:"node_role" yaml:"node_role"`
	Instances []EC2Instance `json:"instances" yaml:"instances"`
}

type ClusterInfo struct {
	eksTypes.Cluster
	NodeGroups []NodeGroup `json:"node_groups" yaml:"node_groups"`
}

type AWSResources struct {
	EKSClusters []ClusterInfo `json:"eks_clusters" yaml:"eks_clusters"`
}

type AWSResourceReport struct {
	Resources AWSResources `json:"resources"`
	Errors    []string     `json:"errors"`
}

func EnumerateEks(ctx context.Context, cfg aws.Config) (*AWSResourceReport, error) {
	eksSvc := eks.NewFromConfig(cfg)
	resources := AWSResources{}
	errors := []string{}

	clusterList, err := eksSvc.ListClusters(ctx, &eks.ListClustersInput{})
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{Errors: errors}, err
	}

	for _, clusterName := range clusterList.Clusters {
		clusterDetail, err := eksSvc.DescribeCluster(ctx, &eks.DescribeClusterInput{Name: &clusterName})
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		cluster := ClusterInfo{Cluster: *clusterDetail.Cluster}

		nodeGroupList, err := eksSvc.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: &clusterName})
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		for _, nodeGroupName := range nodeGroupList.Nodegroups {
			nodeGroupDetail, err := eksSvc.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName:   &clusterName,
				NodegroupName: &nodeGroupName,
			})
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			nodeGroup := NodeGroup{
				Name:     nodeGroupName,
				NodeRole: aws.ToString(nodeGroupDetail.Nodegroup.NodeRole),
			}

			// Fetch instances
			var instances []EC2Instance
			rawEc2Instances, err := getInstancesForNodeGroup(ctx, cfg, clusterName, nodeGroupName)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			for _, inst := range rawEc2Instances {
				instance := EC2Instance{
					InstanceID: *inst.InstanceId,
				}
				instances = append(instances, instance)
			}
			nodeGroup.Instances = instances
			cluster.NodeGroups = append(cluster.NodeGroups, nodeGroup)
		}
		resources.EKSClusters = append(resources.EKSClusters, cluster)
	}

	report := AWSResourceReport{
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}

func getInstancesForNodeGroup(ctx context.Context, cfg aws.Config, clusterName, nodeGroupName string) ([]ec2Types.Instance, error) {
	eksSvc := eks.NewFromConfig(cfg)
	asSvc := autoscaling.NewFromConfig(cfg)
	ec2Svc := ec2.NewFromConfig(cfg)

	// Describe the node group to get the associated ASG name
	nodeGroupOutput, err := eksSvc.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
		ClusterName:   &clusterName,
		NodegroupName: &nodeGroupName,
	})
	if err != nil {
		return nil, err
	}

	// Get the name of the ASG from the node group description
	var asgName string
	for _, asg := range nodeGroupOutput.Nodegroup.Resources.AutoScalingGroups {
		asgName = *asg.Name
		break // Assuming one ASG per node group, which is typical
	}

	// Describe ASG to get the instance IDs
	asgDesc, err := asSvc.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{
		AutoScalingGroupNames: []string{asgName},
	})
	if err != nil {
		return nil, err
	}

	var instanceIDs []string
	for _, group := range asgDesc.AutoScalingGroups {
		for _, instance := range group.Instances {
			instanceIDs = append(instanceIDs, *instance.InstanceId)
		}
	}

	// Describe EC2 instances by their IDs
	ec2Desc, err := ec2Svc.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
		InstanceIds: instanceIDs,
	})
	if err != nil {
		return nil, err
	}

	var instances []ec2Types.Instance
	for _, reservation := range ec2Desc.Reservations {
		instances = append(instances, reservation.Instances...)
	}

	return instances, nil
}
