package common

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/palantir/witchcraft-go-logging/wlog"

	// Import wlog-zap for its side effects, initializing the zap logger
	_ "github.com/palantir/witchcraft-go-logging/wlog-zap"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func GetAWSRegions(ctx context.Context, cfg aws.Config, selectedRegions []string) ([]string, error) {
	logger := svc1log.New(os.Stdout, wlog.InfoLevel)
	ctx = svc1log.WithLogger(ctx, logger)
	log := svc1log.FromContext(ctx)

	log.Info("Starting GetAWSRegions function")

	regionsToCheck := getRegionsToCheck(selectedRegions, log)
	return checkRegions(ctx, cfg, regionsToCheck, log)
}

func getRegionsToCheck(selectedRegions []string, log svc1log.Logger) []string {
	if len(selectedRegions) > 0 {
		log.Info(fmt.Sprintf("Using selected regions: %v", selectedRegions))
		return selectedRegions
	}

	log.Info("No regions selected, checking all regions")
	var allRegions []string
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()

	for _, p := range partitions {
		for region := range p.Regions() {
			allRegions = append(allRegions, region)
		}
	}
	log.Info(fmt.Sprintf("All regions to check: %v", allRegions))
	return allRegions
}

func checkRegions(ctx context.Context, cfg aws.Config, regionsToCheck []string, log svc1log.Logger) ([]string, error) {
	invalidTokenErrors := []string{}

	for _, region := range regionsToCheck {
		log.Info(fmt.Sprintf("Attempting DescribeRegions for region: %s", region))
		validRegions, err := describeRegionsForRegion(ctx, cfg, region, regionsToCheck)
		if err == nil {
			return validRegions, nil
		}

		if handleRegionError(err, region, log, &invalidTokenErrors) {
			return nil, err
		}
	}

	if len(invalidTokenErrors) > 0 {
		return nil, fmt.Errorf("invalid AWS token for one or more regions: %s", strings.Join(invalidTokenErrors, "; "))
	}

	return nil, fmt.Errorf("no accessible regions found among the specified regions")
}

func describeRegionsForRegion(ctx context.Context, cfg aws.Config, region string, regionsToCheck []string) ([]string, error) {
	testCfg := cfg.Copy()
	testCfg.Region = region
	ec2Client := ec2.NewFromConfig(testCfg)
	describeRegionsOutput, err := ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return nil, err
	}

	enabledRegions := make(map[string]bool)
	for _, r := range describeRegionsOutput.Regions {
		enabledRegions[*r.RegionName] = true
	}

	var validRegions []string
	for _, r := range regionsToCheck {
		if enabledRegions[r] {
			validRegions = append(validRegions, r)
		}
	}

	if len(validRegions) == 0 {
		return nil, fmt.Errorf("no enabled regions found among the specified regions")
	}

	return validRegions, nil
}

func handleRegionError(err error, region string, log svc1log.Logger, invalidTokenErrors *[]string) bool {
	errMsg := err.Error()
	if strings.Contains(errMsg, "ExpiredToken") || strings.Contains(errMsg, "RequestExpired") {
		log.Error(fmt.Sprintf("AWS token has expired: %s", errMsg))
		return true
	} else if strings.Contains(errMsg, "InvalidClientTokenId") || strings.Contains(errMsg, "AuthFailure") {
		*invalidTokenErrors = append(*invalidTokenErrors, fmt.Sprintf("Region %s: %s", region, errMsg))
		log.Warn(fmt.Sprintf("Token is invalid for region %s: %v", region, err))
	} else if strings.Contains(errMsg, "no such host") {
		log.Warn(fmt.Sprintf("Region %s is not accessible: %v", region, err))
	} else {
		log.Error(fmt.Sprintf("DescribeRegions failed for region %s: %v", region, err))
	}
	return false
}
