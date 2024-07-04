package loadbalancer

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
)

func EnumerateV1ELBs(ctx context.Context, cfg aws.Config) methodaws.LoadBalancerReport {
	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})

	loadBalancers := []*methodaws.LoadBalancerV1{}
	errorMessages := []string{}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return methodaws.LoadBalancerReport{
				V1LoadBalancers: loadBalancers,
				Errors:          errorMessages,
			}
		}

		for _, lb := range page.LoadBalancerDescriptions {
			loadBalancer := methodaws.LoadBalancerV1{
				Name:             aws.ToString(lb.LoadBalancerName),
				CreatedTime:      aws.ToTime(lb.CreatedTime),
				DnsName:          aws.ToString(lb.DNSName),
				SecurityGroupIds: lb.SecurityGroups,
				VpcId:            aws.ToString(lb.VPCId),
				SubnetIds:        lb.Subnets,
				HostedZoneId:     lb.CanonicalHostedZoneNameID,
			}
			targets, errors := targetsForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.Targets = targets
			loadBalancers = append(loadBalancers, &loadBalancer)
		}
	}
	return methodaws.LoadBalancerReport{
		V1LoadBalancers: loadBalancers,
		Errors:          errorMessages,
	}
}

func targetsForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*methodaws.Target, []string) {
	targets := []*methodaws.Target{}
	errorMessages := []string{}

	if len(loadBalancer.Instances) == len(loadBalancer.BackendServerDescriptions) {
		for i, instance := range loadBalancer.Instances {
			backendServer := loadBalancer.BackendServerDescriptions[i]
			target := methodaws.Target{
				Id:   aws.ToString(instance.InstanceId),
				Port: int(aws.ToInt32(backendServer.InstancePort)),
			}
			targets = append(targets, &target)
		}
	} else {
		errorMessages = append(errorMessages, "Mismatch between instances and backend server descriptions")
	}
	return targets, errorMessages
}
