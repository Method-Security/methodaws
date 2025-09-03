package loadbalancer

import (
	"context"
	"fmt"
	"strings"
	"time"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// convertAWSLoadBalancerType converts AWS LoadBalancerTypeEnum to Fern LoadBalancerType
func convertAWSLoadBalancerType(awsType types.LoadBalancerTypeEnum) (loadbalancerfern.LoadBalancerType, error) {
	switch strings.ToUpper(string(awsType)) {
	case "APPLICATION":
		return loadbalancerfern.LoadBalancerTypeApplication, nil
	case "NETWORK":
		return loadbalancerfern.LoadBalancerTypeNetwork, nil
	case "GATEWAY":
		return loadbalancerfern.LoadBalancerTypeGateway, nil
	default:
		return "", fmt.Errorf("unsupported load balancer type: %s", awsType)
	}
}

// enumerateV2LoadBalancersAllRegions enumerates v2 load balancers across all specified regions
func enumerateV2LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*loadbalancerfern.LoadBalancer, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancer
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
func enumerateV2LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region string) ([]*loadbalancerfern.LoadBalancer, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancingv2.NewFromConfig(cfg)
	paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancingv2.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancer
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to list v2 load balancers in region %s: %s", region, err.Error())
			log.Error("Error listing v2 load balancers", svc1log.SafeParam("error", err.Error()), svc1log.SafeParam("region", region))
			errorMessages = append(errorMessages, errorMsg)
			return loadBalancers, errorMessages
		}

		for _, lb := range page.LoadBalancers {
			var createdTime *time.Time
			if lb.CreatedTime != nil {
				createdTime = lb.CreatedTime
			}
			var dnsName *string
			if lb.DNSName != nil {
				dnsName = lb.DNSName
			}
			loadBalancer := &loadbalancerfern.LoadBalancer{
				Version:          loadbalancerfern.LoadBalancerVersionV2,
				Arn:              lb.LoadBalancerArn,
				Name:             aws.ToString(lb.LoadBalancerName),
				Region:           region,
				CreatedTime:      createdTime,
				DnsName:          dnsName,
				SecurityGroupIds: lb.SecurityGroups,
				VpcId:            lb.VpcId,
				SubnetIds:        getSubnetIds(lb.AvailabilityZones),
				HostedZoneId:     lb.CanonicalHostedZoneId,
			}

			// Convert LoadBalancerType from AWS SDK
			if lbType, err := convertAWSLoadBalancerType(lb.Type); err == nil {
				loadBalancer.LoadBalancerType = &lbType
			} else {
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer type for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
			}

			// Convert IP address type
			if ipType, err := loadbalancerfern.NewIpAddressTypeFromString(strings.ToUpper(string(lb.IpAddressType))); err == nil {
				loadBalancer.IpAddressType = &ipType
			} else {
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert IP address type for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
			}

			// Convert state
			if lb.State != nil {
				if state, err := loadbalancerfern.NewLoadBalancerStateFromString(strings.ToUpper(string(lb.State.Code))); err == nil {
					loadBalancer.State = &state
				} else {
					errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert load balancer state for %s in region %s: %s", aws.ToString(lb.LoadBalancerName), region, err.Error()))
				}
			}

			listeners, errors := listenersForLoadBalancerV2(ctx, client, loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.Listeners = listeners

			targetGroups, errors := targetGroupForLoadBalancerV2(ctx, client, loadBalancer)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}
			loadBalancer.TargetGroups = targetGroups

			loadBalancers = append(loadBalancers, loadBalancer)
		}
	}

	return loadBalancers, errorMessages
}

func listenersForLoadBalancerV2(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer *loadbalancerfern.LoadBalancer) ([]*loadbalancerfern.Listener, []string) {
	listeners := []*loadbalancerfern.Listener{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeListenersPaginator(client, &elasticloadbalancingv2.DescribeListenersInput{
		LoadBalancerArn: loadBalancer.Arn,
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
			if listener.Protocol != "" {
				if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(string(listener.Protocol))); err == nil {
					fernListener.Protocol = &protocol
				} else {
					errorMessages = append(errorMessages, "Failed to convert listener protocol: "+err.Error())
				}
			}

			listeners = append(listeners, fernListener)
		}
	}
	return listeners, errorMessages
}

func targetGroupForLoadBalancerV2(ctx context.Context, client *elasticloadbalancingv2.Client, loadBalancer *loadbalancerfern.LoadBalancer) ([]*loadbalancerfern.TargetGroup, []string) {
	targetGroups := []*loadbalancerfern.TargetGroup{}
	errorMessages := []string{}
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(client, &elasticloadbalancingv2.DescribeTargetGroupsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMessages = append(errorMessages, err.Error())
			return targetGroups, errorMessages
		}

		for _, awsTargetGroup := range page.TargetGroups {
			// Filter target groups by load balancer ARN
			isAttachedToLB := false
			for _, lbArn := range awsTargetGroup.LoadBalancerArns {
				if lbArn == aws.ToString(loadBalancer.Arn) {
					isAttachedToLB = true
					break
				}
			}
			if !isAttachedToLB {
				continue
			}
			targetGroup := &loadbalancerfern.TargetGroup{
				Arn:              aws.ToString(awsTargetGroup.TargetGroupArn),
				Name:             aws.ToString(awsTargetGroup.TargetGroupName),
				Port:             int(aws.ToInt32(awsTargetGroup.Port)),
				VpcId:            awsTargetGroup.VpcId,
				LoadBalancerArns: awsTargetGroup.LoadBalancerArns,
			}

			// Convert IP address type
			if ipType, err := loadbalancerfern.NewTargetGroupIpAddressTypeFromString(strings.ToUpper(string(awsTargetGroup.IpAddressType))); err == nil {
				targetGroup.IpAddressType = ipType
			} else {
				errorMessages = append(errorMessages, "Failed to convert target group IP address type: "+err.Error())
			}

			// Convert protocol
			if awsTargetGroup.Protocol != "" {
				if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(string(awsTargetGroup.Protocol))); err == nil {
					targetGroup.Protocol = &protocol
				} else {
					errorMessages = append(errorMessages, "Failed to convert target group protocol: "+err.Error())
				}
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
	return targetGroups, errorMessages
}

// targetsForTargetGroupV2 converts AWS TargetGroup to Fern Target
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
	if tt, err := loadbalancerfern.NewTargetTypeFromString(strings.ToUpper(string(targetGroup.TargetType))); err == nil {
		targetType = tt
	} else {
		return targets, fmt.Errorf("failed to convert target type: %w", err)
	}
	for _, targetHealth := range output.TargetHealthDescriptions {
		var availabilityZone *string = nil
		if targetHealth.Target.AvailabilityZone != nil {
			availabilityZone = targetHealth.Target.AvailabilityZone
		}
		portValue := int(aws.ToInt32(targetHealth.Target.Port))
		targets = append(targets, &loadbalancerfern.Target{
			Id:               aws.ToString(targetHealth.Target.Id),
			Port:             &portValue,
			Type:             targetType,
			AvailabilityZone: availabilityZone,
		})
	}
	return targets, nil
}

// certificatesForListenerV2 converts AWS Certificate to Fern Certificate
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

// getSubnetIds converts AWS AvailabilityZone to Fern SubnetId
func getSubnetIds(availabilityZones []types.AvailabilityZone) []string {
	subnetIds := []string{}
	for _, az := range availabilityZones {
		subnetIds = append(subnetIds, aws.ToString(az.SubnetId))
	}
	return subnetIds
}
