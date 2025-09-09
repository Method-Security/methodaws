// Package route53 provides logic and data structures necessary to enumerate and integrate AWS Route 53 resources.
package route53

import (
	// Standard
	"context"
	"strings"

	// Generated
	route53fern "github.com/Method-Security/methodaws/generated/go/route53"
	// Internal
	// External
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// REGION is the region to use for Route53 enumeration.
// Route53 is a global service, so we only need to query once.
const (
	REGION = "us-east-1"
)

func listHostedZones(ctx context.Context, route53Client *route53.Client) ([]route53fern.EnrichedHostedZone, error) {
	log := svc1log.FromContext(ctx)
	var zones []route53fern.EnrichedHostedZone

	log.Info("Starting Route53 hosted zones enumeration")
	paginator := route53.NewListHostedZonesPaginator(route53Client, &route53.ListHostedZonesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Failed to get next page of hosted zones", svc1log.Stacktrace(err))
			return nil, err
		}

		log.Info("Retrieved hosted zones page", svc1log.SafeParam("zoneCount", len(page.HostedZones)))

		for _, hostedZone := range page.HostedZones {
			// Convert AWS SDK HostedZone to fern HostedZoneDetails
			zoneDetails := route53fern.HostedZoneDetails{
				CallerReference: *hostedZone.CallerReference,
				Id:              *hostedZone.Id,
				Name:            *hostedZone.Name,
			}

			// Add optional fields if they exist
			if hostedZone.Config != nil {
				if hostedZone.Config.Comment != nil {
					hostedZoneConfig := route53fern.HostedZone{
						Comment:     hostedZone.Config.Comment,
						PrivateZone: hostedZone.Config.PrivateZone,
					}
					zoneDetails.HostedZone = &hostedZoneConfig
				} else {
					hostedZoneConfig := route53fern.HostedZone{
						PrivateZone: hostedZone.Config.PrivateZone,
					}
					zoneDetails.HostedZone = &hostedZoneConfig
				}
			}

			if hostedZone.ResourceRecordSetCount != nil {
				recordCount := int(*hostedZone.ResourceRecordSetCount)
				zoneDetails.ResourceRecordSetCount = &recordCount
			}

			if hostedZone.LinkedService != nil {
				linkedService := route53fern.LinkedService{
					ServicePrincipal: hostedZone.LinkedService.ServicePrincipal,
					Description:      hostedZone.LinkedService.Description,
				}
				zoneDetails.LinkedService = &linkedService
			}

			zone := route53fern.EnrichedHostedZone{
				ZoneDetails: &zoneDetails,
			}

			log.Info("Processing hosted zone", svc1log.SafeParam("zoneName", zoneDetails.Name), svc1log.SafeParam("zoneId", zoneDetails.Id))

			resourceRecordSets, err := listDNSRecords(ctx, route53Client, zoneDetails.Id)
			if err != nil {
				log.Error("Failed to get DNS records for hosted zone",
					svc1log.SafeParam("zoneName", zoneDetails.Name),
					svc1log.SafeParam("zoneId", zoneDetails.Id),
					svc1log.Stacktrace(err))
				return nil, err
			}

			zone.ResourceRecordSets = resourceRecordSets
			zones = append(zones, zone)

			log.Info("Successfully processed hosted zone",
				svc1log.SafeParam("zoneName", zoneDetails.Name),
				svc1log.SafeParam("recordCount", len(resourceRecordSets)))
		}
	}

	log.Info("Completed Route53 hosted zones enumeration", svc1log.SafeParam("totalZones", len(zones)))
	return zones, nil
}

func listDNSRecords(ctx context.Context, route53Client *route53.Client, zoneID string) ([]*route53fern.ResourceRecordSet, error) {
	log := svc1log.FromContext(ctx)
	var recordSets []*route53fern.ResourceRecordSet

	log.Info("Retrieving DNS records for zone", svc1log.SafeParam("zoneId", zoneID))

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}

	paginator := route53.NewListResourceRecordSetsPaginator(route53Client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			log.Error("Failed to get next page of DNS records",
				svc1log.SafeParam("zoneId", zoneID),
				svc1log.Stacktrace(err))
			return nil, err
		}

		log.Info("Retrieved DNS records page",
			svc1log.SafeParam("zoneId", zoneID),
			svc1log.SafeParam("recordCount", len(page.ResourceRecordSets)))

		for _, recordSet := range page.ResourceRecordSets {
			// Convert AWS SDK ResourceRecordSet to fern ResourceRecordSet
			fernRecord := &route53fern.ResourceRecordSet{
				Name: *recordSet.Name,
				Type: route53fern.RecordType(strings.ToUpper(string(recordSet.Type))),
			}

			// Handle optional fields
			if recordSet.AliasTarget != nil {
				aliasTarget := &route53fern.AliasTarget{
					DnsName:              *recordSet.AliasTarget.DNSName,
					HostedZoneId:         *recordSet.AliasTarget.HostedZoneId,
					EvaluateTargetHealth: recordSet.AliasTarget.EvaluateTargetHealth,
				}
				fernRecord.AliasTarget = aliasTarget
			}

			if recordSet.CidrRoutingConfig != nil {
				cidrRouting := &route53fern.CidrRouting{
					CollectionId: *recordSet.CidrRoutingConfig.CollectionId,
					LocationName: *recordSet.CidrRoutingConfig.LocationName,
				}
				fernRecord.CidrRouting = cidrRouting
			}

			if recordSet.Failover != "" {
				failover := string(recordSet.Failover)
				fernRecord.Failover = &failover
			}

			if recordSet.GeoLocation != nil {
				geoLocation := &route53fern.GeoLocation{
					ContinentCode:   recordSet.GeoLocation.ContinentCode,
					CountryCode:     recordSet.GeoLocation.CountryCode,
					SubdivisionCode: recordSet.GeoLocation.SubdivisionCode,
				}
				fernRecord.GeoLocation = geoLocation
			}

			if recordSet.HealthCheckId != nil {
				fernRecord.HealthCheckId = recordSet.HealthCheckId
			}

			if recordSet.MultiValueAnswer != nil {
				fernRecord.MultiValueAnswer = recordSet.MultiValueAnswer
			}

			if recordSet.Region != "" {
				region := string(recordSet.Region)
				fernRecord.Region = &region
			}

			if recordSet.ResourceRecords != nil {
				var resourceRecords []*route53fern.ResourceRecord
				for _, rr := range recordSet.ResourceRecords {
					resourceRecord := &route53fern.ResourceRecord{
						Value: *rr.Value,
					}
					resourceRecords = append(resourceRecords, resourceRecord)
				}
				fernRecord.ResourceRecords = resourceRecords
			}

			if recordSet.SetIdentifier != nil {
				fernRecord.SetIdentifier = recordSet.SetIdentifier
			}

			if recordSet.TTL != nil {
				ttl := int(*recordSet.TTL)
				fernRecord.Ttl = &ttl
			}

			if recordSet.Weight != nil {
				weight := int(*recordSet.Weight)
				fernRecord.Weight = &weight
			}

			recordSets = append(recordSets, fernRecord)
		}
	}

	log.Info("Completed DNS records retrieval",
		svc1log.SafeParam("zoneId", zoneID),
		svc1log.SafeParam("totalRecords", len(recordSets)))

	return recordSets, nil
}

// EnumerateRoute53 retrieves all Route 53 hosted zones available to the caller and returns a Route53EnumerateReport struct
func EnumerateRoute53(ctx context.Context, awscfg aws.Config, config route53fern.Route53EnumerateConfig) *route53fern.Route53EnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Route53 enumeration")

	// Set the region to us-east-1 for since Route53 is a global resounce and ignore the region data
	awscfg.Region = REGION

	// Initialize Report
	report := route53fern.Route53EnumerateReport{
		Result: &route53fern.Route53Result{},
		Config: &config,
	}
	var errors []string

	// Create a new AWS config for this region
	route53Client := route53.NewFromConfig(awscfg)

	// List hosted zones
	hostedZones, err := listHostedZones(ctx, route53Client)
	if err != nil {
		log.Error("Failed to list hosted zones",
			svc1log.SafeParam("region", awscfg.Region),
			svc1log.Stacktrace(err))
		errors = append(errors, err.Error())
	}

	// Add hosted zones to report
	result := route53fern.Route53Result{}
	if len(hostedZones) > 0 {
		// Convert to slice of pointers
		var hostedZonePointers []*route53fern.EnrichedHostedZone
		for i := range hostedZones {
			hostedZonePointers = append(hostedZonePointers, &hostedZones[i])
		}
		result.HostedZones = hostedZonePointers
	}

	// Only add hosted zones if there are any
	if len(result.HostedZones) > 0 {
		report.Result.HostedZones = result.HostedZones
	}
	report.Errors = errors
	return &report
}
