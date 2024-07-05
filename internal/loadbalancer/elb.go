package loadbalancer

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
)

func EnumerateV1ELBs(ctx context.Context, cfg aws.Config) methodaws.LoadBalancerReport {
	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})

	loadBalancers := []*methodaws.LoadBalancerV1{}
	errorMessages := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.LoadBalancerReport{
			AccountId:       aws.ToString(accountID),
			V1LoadBalancers: loadBalancers,
			Errors:          errorMessages,
		}
	}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return methodaws.LoadBalancerReport{
				AccountId:       aws.ToString(accountID),
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

			listeners, errors := listenersForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.Listeners = listeners

			loadBalancers = append(loadBalancers, &loadBalancer)
		}
	}
	return methodaws.LoadBalancerReport{
		AccountId:       aws.ToString(accountID),
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

func listenersForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*methodaws.Listener, []string) {
	listeners := []*methodaws.Listener{}
	errorMessages := []string{}

	for _, listener := range loadBalancer.ListenerDescriptions {
		listener := methodaws.Listener{
			Protocol: convertProtocolFromString(listener.Listener.Protocol),
			Port:     int(listener.Listener.LoadBalancerPort),
		}
		listeners = append(listeners, &listener)
	}
	return listeners, errorMessages
}
