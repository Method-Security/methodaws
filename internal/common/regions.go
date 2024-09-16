package common

import (
	"context"
	"fmt"
	"strings"

	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go/aws/endpoints"
)

func GetAWSRegions(ctx context.Context, cfg aws.Config, selectedRegions []string) ([]string, error) {
	log.Println("Starting GetAWSRegions function")

	var regionsToCheck []string
	if len(selectedRegions) > 0 {
		regionsToCheck = selectedRegions
		log.Printf("Using selected regions: %v\n", regionsToCheck)
	} else {
		log.Println("No regions selected, checking all regions")
		resolver := endpoints.DefaultResolver()
		partitions := resolver.(endpoints.EnumPartitions).Partitions()

		for _, p := range partitions {
			for region := range p.Regions() {
				regionsToCheck = append(regionsToCheck, region)
			}
		}
		log.Printf("All regions to check: %v\n", regionsToCheck)
	}

	// Find an enabled region
	log.Println("Attempting to find an enabled region")
	var enabledRegion string
	var expiredToken bool
	invalidTokenErrors := []string{}
	for _, region := range regionsToCheck {
		log.Printf("Checking region: %s\n", region)
		testCfg := cfg.Copy()
		testCfg.Region = region
		stsClient := sts.NewFromConfig(testCfg)
		_, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err == nil {
			enabledRegion = region
			log.Printf("Found enabled region: %s\n", enabledRegion)
			break
		} else {
			errMsg := err.Error()
			if strings.Contains(errMsg, "ExpiredToken") {
				expiredToken = true
				log.Printf("Token is expired: %v\n", err)
				break
			} else if strings.Contains(errMsg, "InvalidClientTokenId") {
				invalidTokenErrors = append(invalidTokenErrors, fmt.Sprintf("Region %s: %s", region, errMsg))
				log.Printf("Token is invalid for region %s: %v\n", region, err)
			} else if strings.Contains(errMsg, "no such host") {
				log.Printf("Region %s is not accessible: %v\n", region, err)
			} else {
				log.Printf("Region %s is not enabled: %v\n", region, err)
			}
		}
	}

	if expiredToken {
		return nil, fmt.Errorf("the AWS token has expired")
	}

	if len(invalidTokenErrors) > 0 && enabledRegion == "" {
		return nil, fmt.Errorf("invalid AWS token for one or more regions: %s", strings.Join(invalidTokenErrors, "; "))
	}

	if enabledRegion == "" {
		return nil, fmt.Errorf("no accessible regions found among the specified regions")
	}

	log.Printf("Using enabled region %s to describe all enabled regions\n", enabledRegion)
	cfg.Region = enabledRegion
	ec2Client := ec2.NewFromConfig(cfg)
	describeRegionsOutput, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to describe regions: %w", err)
	}

	log.Printf("DescribeRegions successful, found %d regions\n", len(describeRegionsOutput.Regions))

	enabledRegions := make(map[string]bool)
	for _, region := range describeRegionsOutput.Regions {
		enabledRegions[*region.RegionName] = true
	}

	// Find the intersection of regions to check and enabled regions
	var validRegions []string
	for _, region := range regionsToCheck {
		if enabledRegions[region] {
			validRegions = append(validRegions, region)
		}
	}

	log.Printf("Final valid regions: %v\n", validRegions)

	if len(validRegions) == 0 {
		return nil, fmt.Errorf("no enabled regions found among the specified regions")
	}

	return validRegions, nil
}
