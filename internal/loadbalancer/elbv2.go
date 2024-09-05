package loadbalancer

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
)

func EnumerateV2LBs(ctx context.Context, cfg aws.Config) methodaws.LoadBalancerReport {
	client := elasticloadbalancingv2.NewFromConfig(cfg)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	loadBalancers := []*methodaws.LoadBalancerV2{}
	errorMessages := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errorMessages = append(errorMessages, err.Error())
		return methodaws.LoadBalancerReport{
			AccountId:       aws.ToString(accountID),
			V2LoadBalancers: loadBalancers,
			Errors:          errorMessages,
		}
	}

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return methodaws.LoadBalancerReport{
				AccountId:       aws.ToString(accountID),
				V2LoadBalancers: loadBalancers,
				Errors:          errorMessages,
			}
		}

		for _, lb := range page.LoadBalancers {
			loadBalancer := methodaws.LoadBalancerV2{
				Arn:              aws.ToString(lb.LoadBalancerArn),
				Name:             aws.ToString(lb.LoadBalancerName),
				CreatedTime:      aws.ToTime(lb.CreatedTime),
				DnsName:          aws.ToString(lb.DNSName),
				IpAddressType:    convertIPAddressType(lb.IpAddressType),
				SecurityGroupIds: lb.SecurityGroups,
				State:            loadBalancerCodeToState(lb.State),
				VpcId:            lb.VpcId,
				SubnetIds:        getSubnetIds(lb.AvailabilityZones),
			}

			listeners, errors := listenersForLoadBalancer(ctx, client, loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.Listeners = listeners

			targetGroups, errors := targetGroupForLoadBalancer(ctx, client, loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.TargetGroups = targetGroups

			loadBalancers = append(loadBalancers, &loadBalancer)
		}
	}
	return methodaws.LoadBalancerReport{
		AccountId:       aws.ToString(accountID),
		V2LoadBalancers: loadBalancers,
		Errors:          errorMessages,
	}
}

func listenersForLoadBalancer(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer methodaws.LoadBalancerV2) ([]*methodaws.Listener, []string) {
	listeners := []*methodaws.Listener{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeListenersPaginator(client, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: &loadBalancer.Arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return listeners, errorMessages
		}

		for _, listener := range page.Listeners {
			listeners = append(listeners, &methodaws.Listener{
				Arn:             listener.ListenerArn,
				Port:            int(aws.ToInt32(listener.Port)),
				Protocol:        convertProtocol(listener.Protocol),
				LoadBalancerArn: listener.LoadBalancerArn,
				Certificates:    certificatesForListener(listener.Certificates),
			})
		}
	}
	return listeners, errorMessages
}

func targetGroupForLoadBalancer(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer methodaws.LoadBalancerV2) ([]*methodaws.TargetGroup, []string) {
	targetGroups := []*methodaws.TargetGroup{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{
		LoadBalancerArn: &loadBalancer.Arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return targetGroups, errorMessages
		}

		for _, awsTargetGroup := range page.TargetGroups {
			targetGroup := methodaws.TargetGroup{
				Arn:             aws.ToString(awsTargetGroup.TargetGroupArn),
				Name:            aws.ToString(awsTargetGroup.TargetGroupName),
				IpAddressType:   convertTargetGroupIPAddressType(awsTargetGroup.IpAddressType),
				Port:            int(aws.ToInt32(awsTargetGroup.Port)),
				Protocol:        convertProtocol(awsTargetGroup.Protocol),
				VpcId:           awsTargetGroup.VpcId,
				LoadBalancerArn: awsTargetGroup.LoadBalancerArns[0],
			}

			targets, err := targetsForTargetGroup(ctx, client, awsTargetGroup)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			targetGroup.Targets = targets
			targetGroups = append(targetGroups, &targetGroup)
		}
	}
	return targetGroups, nil
}

func targetsForTargetGroup(ctx context.Context, client *elasticloadbalancingv2.Client, targetGroup types.TargetGroup) ([]*methodaws.Target, error) {
	var targets []*methodaws.Target
	output, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: targetGroup.TargetGroupArn,
	})
	if err != nil {
		return targets, err
	}
	for _, targetHealth := range output.TargetHealthDescriptions {
		var availabilityZone *string = nil
		if targetHealth.Target.AvailabilityZone != nil {
			availabilityZone = targetHealth.Target.AvailabilityZone
		}
		targets = append(targets, &methodaws.Target{
			Id:               aws.ToString(targetHealth.Target.Id),
			Port:             int(aws.ToInt32(targetHealth.Target.Port)),
			Type:             convertTargetGroupType(targetGroup.TargetType),
			AvailabilityZone: availabilityZone,
		})
	}
	return targets, nil
}

func certificatesForListener(certificates []types.Certificate) []*methodaws.Certificate {
	certs := []*methodaws.Certificate{}
	for _, cert := range certificates {
		var isDefault bool
		if cert.IsDefault != nil {
			isDefault = *cert.IsDefault
		} else {
			isDefault = false
		}
		certs = append(certs, &methodaws.Certificate{
			Arn:       aws.ToString(cert.CertificateArn),
			IsDefault: isDefault,
		})
	}
	return certs
}

func getSubnetIds(availabilityZones []types.AvailabilityZone) []string {
	subnetIds := []string{}
	for _, az := range availabilityZones {
		subnetIds = append(subnetIds, aws.ToString(az.SubnetId))
	}
	return subnetIds
}
