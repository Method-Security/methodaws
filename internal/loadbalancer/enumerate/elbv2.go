package loadbalancer

import (
	"context"
	"fmt"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV2LoadBalancersAllRegions enumerates v2 load balancers across all specified regions
func enumerateV2LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*loadbalancerfern.LoadBalancerV2, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancerV2
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v2 load balancers in region", svc1log.SafeParam("region", region))
		loadBalancers, errors := enumerateV2LoadBalancersForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v2 load balancers in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allLoadBalancers = append(allLoadBalancers, loadBalancers...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v2 load balancers in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("loadBalancerCount", len(loadBalancers)))
	}

	return allLoadBalancers, allErrors
}

// enumerateV2LoadBalancersForRegion enumerates v2 load balancers for a specific region
func enumerateV2LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region string) ([]*loadbalancerfern.LoadBalancerV2, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancingv2.NewFromConfig(cfg)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancerV2
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := "Failed to list v2 load balancers: " + err.Error()
			log.Error("Error listing v2 load balancers", svc1log.SafeParam("error", err.Error()))
			errorMessages = append(errorMessages, errorMsg)
			return loadBalancers, errorMessages
		}

		for _, lb := range page.LoadBalancers {
			loadBalancer := &loadbalancerfern.LoadBalancerV2{
				Arn:              aws.ToString(lb.LoadBalancerArn),
				Name:             aws.ToString(lb.LoadBalancerName),
				Region:           region,
				CreatedTime:      aws.ToTime(lb.CreatedTime),
				DnsName:          aws.ToString(lb.DNSName),
				SecurityGroupIds: lb.SecurityGroups,
				VpcId:            lb.VpcId,
				SubnetIds:        getSubnetIds(lb.AvailabilityZones),
				HostedZoneId:     lb.CanonicalHostedZoneId,
			}

			// Convert IP address type
			if ipType, err := loadbalancerfern.NewIpAddressTypeFromString(string(lb.IpAddressType)); err == nil {
				loadBalancer.IpAddressType = ipType
			} else {
				errorMessages = append(errorMessages, "Failed to convert IP address type: "+err.Error())
			}

			// Convert state
			if lb.State != nil {
				if state, err := loadbalancerfern.NewLoadBalancerStateFromString(string(lb.State.Code)); err == nil {
					loadBalancer.State = &state
				} else {
					errorMessages = append(errorMessages, "Failed to convert load balancer state: "+err.Error())
				}
			}

			listeners, errors := listenersForLoadBalancerV2(ctx, client, *loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.Listeners = listeners

			targetGroups, errors := targetGroupForLoadBalancerV2(ctx, client, *loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.TargetGroups = targetGroups

			loadBalancers = append(loadBalancers, loadBalancer)
		}
	}

	return loadBalancers, errorMessages
}

func listenersForLoadBalancerV2(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer loadbalancerfern.LoadBalancerV2) ([]*loadbalancerfern.Listener, []string) {
	listeners := []*loadbalancerfern.Listener{}
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
			fernListener := &loadbalancerfern.Listener{
				Arn:             listener.ListenerArn,
				Port:            int(aws.ToInt32(listener.Port)),
				Certificates:    certificatesForListenerV2(listener.Certificates),
				LoadBalancerArn: listener.LoadBalancerArn,
			}

			// Convert protocol
			if protocol, err := loadbalancerfern.NewProtocolFromString(string(listener.Protocol)); err == nil {
				fernListener.Protocol = &protocol
			} else {
				errorMessages = append(errorMessages, "Failed to convert listener protocol: "+err.Error())
			}

			listeners = append(listeners, fernListener)
		}
	}
	return listeners, errorMessages
}

func targetGroupForLoadBalancerV2(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer loadbalancerfern.LoadBalancerV2) ([]*loadbalancerfern.TargetGroup, []string) {
	targetGroups := []*loadbalancerfern.TargetGroup{}
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
			targetGroup := &loadbalancerfern.TargetGroup{
				Arn:              aws.ToString(awsTargetGroup.TargetGroupArn),
				Name:             aws.ToString(awsTargetGroup.TargetGroupName),
				Port:             int(aws.ToInt32(awsTargetGroup.Port)),
				VpcId:            awsTargetGroup.VpcId,
				LoadBalancerArns: awsTargetGroup.LoadBalancerArns,
			}

			// Convert IP address type
			if ipType, err := loadbalancerfern.NewTargetGroupIpAddressTypeFromString(string(awsTargetGroup.IpAddressType)); err == nil {
				targetGroup.IpAddressType = ipType
			} else {
				errorMessages = append(errorMessages, "Failed to convert target group IP address type: "+err.Error())
			}

			// Convert protocol
			if protocol, err := loadbalancerfern.NewProtocolFromString(string(awsTargetGroup.Protocol)); err == nil {
				targetGroup.Protocol = &protocol
			} else {
				errorMessages = append(errorMessages, "Failed to convert target group protocol: "+err.Error())
			}

			targets, err := targetsForTargetGroupV2(ctx, client, awsTargetGroup)
			if err != nil {
				errorMessages = append(errorMessages, err.Error())
				continue
			}
			targetGroup.Targets = targets
			targetGroups = append(targetGroups, targetGroup)
		}
	}
	return targetGroups, nil
}

func targetsForTargetGroupV2(ctx context.Context, client *elasticloadbalancingv2.Client, targetGroup types.TargetGroup) ([]*loadbalancerfern.Target, error) {
	var targets []*loadbalancerfern.Target
	output, err := client.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: targetGroup.TargetGroupArn,
	})
	if err != nil {
		return targets, err
	}

	// Convert target type once for all targets in this group
	var targetType loadbalancerfern.TargetType
	if tt, err := loadbalancerfern.NewTargetTypeFromString(string(targetGroup.TargetType)); err == nil {
		targetType = tt
	} else {
		return targets, fmt.Errorf("failed to convert target type: %w", err)
	}
	for _, targetHealth := range output.TargetHealthDescriptions {
		var availabilityZone *string = nil
		if targetHealth.Target.AvailabilityZone != nil {
			availabilityZone = targetHealth.Target.AvailabilityZone
		}
		targets = append(targets, &loadbalancerfern.Target{
			Id:               aws.ToString(targetHealth.Target.Id),
			Port:             int(aws.ToInt32(targetHealth.Target.Port)),
			Type:             targetType,
			AvailabilityZone: availabilityZone,
		})
	}
	return targets, nil
}

func certificatesForListenerV2(certificates []types.Certificate) []*loadbalancerfern.Certificate {
	certs := []*loadbalancerfern.Certificate{}
	for _, cert := range certificates {
		var isDefault bool
		if cert.IsDefault != nil {
			isDefault = *cert.IsDefault
		} else {
			isDefault = false
		}
		certs = append(certs, &loadbalancerfern.Certificate{
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
