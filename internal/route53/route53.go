// The route53 package provides logic and data structures necessary to enumerate and integrate AWS Route 53 resources.
package route53

import (
	"context"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
)

// EnrichedHostedZone wraps the AWS representations of a hosted zone and its associated resource record sets.
type EnrichedHostedZone struct {
	ZoneDetails        types.HostedZone          `json:"zone_details" yaml:"zone_details"`
	ResourceRecordSets []types.ResourceRecordSet `json:"resource_record_sets" yaml:"resource_record_sets"`
}

// AWSResources contains the Route 53 hosted zones that were enumerated.
type AWSResources struct {
	HostedZones []EnrichedHostedZone `json:"hosted_zones" yaml:"hosted_zones"`
}

// AWSResourceReport contains the account ID that the Route 53 hosted zones were discovered in, the resources themselves,
// and any non-fatal errors that occurred during the execution of the `methodaws route53 enumerate` subcommand.
type AWSResourceReport struct {
	AccountID string       `json:"account_id" yaml:"account_id"`
	Resources AWSResources `json:"resources" yaml:"resources"`
	Errors    []string     `json:"errors" yaml:"errors"`
}

func listHostedZones(ctx context.Context, route53Client *route53.Client) ([]EnrichedHostedZone, error) {
	var zones []EnrichedHostedZone

	paginator := route53.NewListHostedZonesPaginator(route53Client, &route53.ListHostedZonesInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, hostedZone := range page.HostedZones {
			zone := EnrichedHostedZone{
				ZoneDetails: hostedZone,
			}

			resourceRecordSets, err := listDNSRecords(ctx, route53Client, *zone.ZoneDetails.Id)
			if err != nil {
				return nil, err
			}

			zone.ResourceRecordSets = resourceRecordSets
			zones = append(zones, zone)
		}
	}

	return zones, nil
}

func listDNSRecords(ctx context.Context, route53Client *route53.Client, zoneID string) ([]types.ResourceRecordSet, error) {
	var recordSets []types.ResourceRecordSet

	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneID),
	}

	paginator := route53.NewListResourceRecordSetsPaginator(route53Client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		recordSets = append(recordSets, page.ResourceRecordSets...)
	}

	return recordSets, nil
}

// EnumerateRoute53 retrieves all Route 53 hosted zones available to the caller and returns an AWSResourceReport struct
func EnumerateRoute53(ctx context.Context, cfg aws.Config) (*AWSResourceReport, error) {
	route53Client := route53.NewFromConfig(cfg)
	resources := AWSResources{}
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{Errors: errors}, err
	}

	hostedZones, err := listHostedZones(ctx, route53Client)
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		resources.HostedZones = hostedZones
	}

	report := AWSResourceReport{
		AccountID: *accountID,
		Resources: resources,
		Errors:    errors,
	}

	return &report, nil
}
