package common

import (
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

func GetAWSRegions(selectedRegions []string) []string {
	if len(selectedRegions) > 0 {
		return selectedRegions
	}

	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()

	var regions []string
	for _, p := range partitions {
		for region := range p.Regions() {
			regions = append(regions, region)
		}
	}

	return regions
}
