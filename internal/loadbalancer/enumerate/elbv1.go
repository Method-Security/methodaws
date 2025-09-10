package loadbalancer

import (
	"context"
	"fmt"
	"strings"

	loadbalancerfern "github.com/Method-Security/methodaws/generated/go/loadbalancer"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1LoadBalancersAllRegions enumerates v1 load balancers across all specified regions
func enumerateV1LoadBalancersAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allLoadBalancers []*loadbalancerfern.LoadBalancerInstance
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
func enumerateV1LoadBalancersForRegion(ctx context.Context, cfg aws.Config, region string) ([]*loadbalancerfern.LoadBalancerInstance, []string) {
	log := svc1log.FromContext(ctx)
	cfg.Region = region

	client := elasticloadbalancing.NewFromConfig(cfg)
	paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(client, &elasticloadbalancing.DescribeLoadBalancersInput{})

	var loadBalancers []*loadbalancerfern.LoadBalancerInstance
	var errorMessages []string

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to list v1 load balancers in region %s: %s", region, err.Error())
			log.Error("Error listing v1 load balancers", svc1log.SafeParam("error", err.Error()), svc1log.SafeParam("region", region))
			errorMessages = append(errorMessages, errorMsg)
			return loadBalancers, errorMessages
		}

		for _, lb := range page.LoadBalancerDescriptions {
			if lb.LoadBalancerName == nil {
				log.Warn("LoadBalancer name is nil for load balancer", svc1log.SafeParam("loadBalancer", lb))
				errorMessages = append(errorMessages, "LoadBalancer name is nil")
				continue
			}

			// Create identification info
			identification := &loadbalancerfern.LoadBalancerIdentificationInfo{
				Id:     aws.ToString(lb.LoadBalancerName),
				Region: region,
			}

			// Create configuration info
			configuration := &loadbalancerfern.LoadBalancerConfigurationInfo{
				Name:             lb.LoadBalancerName,
				LoadBalancerType: loadbalancerfern.LoadBalancerTypeClassic,
				DnsName:          lb.DNSName,
				CreatedTime:      lb.CreatedTime,
				HostedZoneId:     lb.CanonicalHostedZoneNameID,
			}

			// Get targets and listeners
			targets, errors := targetsForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			listeners, errors := listenersForLoadBalancerV1(lb)
			if len(errors) > 0 {
				errorMessages = append(errorMessages, errors...)
			}

			// Create VPC instance if VPCId exists
			var vpc *loadbalancerfern.VpcInstance
			if lb.VPCId != nil {
				vpc = &loadbalancerfern.VpcInstance{
					Identification: &loadbalancerfern.VpcIdentificationInfo{
						Id: aws.ToString(lb.VPCId),
					},
					Resources: &loadbalancerfern.VpcResourceInfo{
						SubnetIds: lb.Subnets,
					},
				}
			}

			// Create resource info
			resources := &loadbalancerfern.LoadBalancerResourceInfo{
				Listeners:        listeners,
				Targets:          targets,
				Vpc:              vpc,
				SecurityGroupIds: lb.SecurityGroups,
			}

			// Create LoadBalancerInstance
			loadBalancer := &loadbalancerfern.LoadBalancerInstance{
				Identification: identification,
				Configuration:  configuration,
				Resources:      resources,
			}

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
			var port *int
			if backendServer.InstancePort != nil {
				portValue := int(*backendServer.InstancePort)
				port = &portValue
			}
			targetType := loadbalancerfern.TargetTypeInstance
			target := &loadbalancerfern.Target{
				Id:   aws.ToString(instance.InstanceId),
				Type: &targetType, // Classic ELB can only point to EC2 instances
				Port: port,
			}
			targets = append(targets, target)
		}
	} else {
		errorMessages = append(errorMessages, fmt.Sprintf("Mismatch between instances (%d) and backend server descriptions (%d) for load balancer %s",
			len(loadBalancer.Instances), len(loadBalancer.BackendServerDescriptions), aws.ToString(loadBalancer.LoadBalancerName)))
	}
	return targets, errorMessages
}

func listenersForLoadBalancerV1(loadBalancer types.LoadBalancerDescription) ([]*loadbalancerfern.Listener, []string) {
	listeners := []*loadbalancerfern.Listener{}
	errorMessages := []string{}

	for _, listener := range loadBalancer.ListenerDescriptions {
		port := int(listener.Listener.LoadBalancerPort)
		fernListener := &loadbalancerfern.Listener{
			Port: &port,
		}

		// Convert protocol
		if listener.Listener.Protocol != nil {
			if protocol, err := loadbalancerfern.NewProtocolFromString(strings.ToUpper(*listener.Listener.Protocol)); err == nil {
				fernListener.Protocol = &protocol
			} else {
				errorMessages = append(errorMessages, fmt.Sprintf("Failed to convert listener protocol for load balancer %s: %s", aws.ToString(loadBalancer.LoadBalancerName), err.Error()))
			}
		}

		listeners = append(listeners, fernListener)
	}
	return listeners, errorMessages
}
