package loadbalancer

import (
	"context"
	"strings"
	"time"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1LoadBalancersAllRegions enumerates v1 load balancers across all specified regions
func enumerateV1LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*loadbalancerfern.LoadBalancer, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancer
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v1 load balancers in region", svc1log.SafeParam("region", region))
		loadBalancers, errors := enumerateV1LoadBalancersForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v1 load balancers in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allLoadBalancers = append(allLoadBalancers, loadBalancers...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v1 load balancers in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("loadBalancerCount", len(loadBalancers)))
	}

	return allLoadBalancers, allErrors
}

// enumerateV1LoadBalancersForRegion enumerates v1 load balancers for a specific region
func enumerateV1LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region string) ([]*loadbalancerfern.LoadBalancer, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancer
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := "Failed to list v1 load balancers: " + err.Error()
			log.Error("Error listing v1 load balancers", svc1log.SafeParam("error", err.Error()))
			errorMessages = append(errorMessages, errorMsg)
			return loadBalancers, errorMessages
		}

		for _, lb := range page.LoadBalancerDescriptions {
			lbType := loadbalancerfern.LoadBalancerTypeClassic
			var createdTime *time.Time
			if lb.CreatedTime != nil {
				createdTime = lb.CreatedTime
			}
			var dnsName *string
			if lb.DNSName != nil {
				dnsName = lb.DNSName
			}
			loadBalancer := &loadbalancerfern.LoadBalancer{
				Version:          loadbalancerfern.LoadBalancerVersionV1,
				LoadBalancerType: &lbType,
				Name:             aws.ToString(lb.LoadBalancerName),
				Region:           region,
				CreatedTime:      createdTime,
				DnsName:          dnsName,
				SecurityGroupIds: lb.SecurityGroups,
				VpcId:            lb.VPCId,
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

			loadBalancers = append(loadBalancers, loadBalancer)
		}
	}

	return loadBalancers, errorMessages
}

func targetsForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*loadbalancerfern.Target, []string) {
	targets := []*loadbalancerfern.Target{}
	errorMessages := []string{}

	if len(loadBalancer.Instances) == len(loadBalancer.BackendServerDescriptions) {
		for i, instance := range loadBalancer.Instances {
			backendServer := loadBalancer.BackendServerDescriptions[i]
			target := &loadbalancerfern.Target{
				Id:   aws.ToString(instance.InstanceId),
				Type: loadbalancerfern.TargetTypeInstance,
				Port: int(aws.ToInt32(backendServer.InstancePort)),
			}
			targets = append(targets, target)
		}
	} else {
		errorMessages = append(errorMessages, "Mismatch between instances and backend server descriptions")
	}
	return targets, errorMessages
}

func listenersForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*loadbalancerfern.Listener, []string) {
	listeners := []*loadbalancerfern.Listener{}
	errorMessages := []string{}

	for _, listener := range loadBalancer.ListenerDescriptions {
		fernListener := &loadbalancerfern.Listener{
			Port: int(listener.Listener.LoadBalancerPort),
		}

		// Convert protocol
		if listener.Listener.Protocol != nil {
			if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(*listener.Listener.Protocol)); err == nil {
				fernListener.Protocol = &protocol
			} else {
				errorMessages = append(errorMessages, "Failed to convert listener protocol: "+err.Error())
			}
		}

		listeners = append(listeners, fernListener)
	}
	return listeners, errorMessages
}
