package route53

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"gitlab.com/method-security/cyber-tools/methodaws/internal/sts"
)

type EnrichedHostedZone struct {
	ZoneDetails        types.HostedZone          `json:"zone_details" yaml:"zone_details"`
	ResourceRecordSets []types.ResourceRecordSet `json:"resource_record_sets" yaml:"resource_record_sets"`
}

type AWSResources struct {
	HostedZones []EnrichedHostedZone `json:"hosted_zones" yaml:"hosted_zones"`
}

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
