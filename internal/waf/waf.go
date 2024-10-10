package waf

import (
	"context"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func EnumerateWAF(ctx context.Context, cloudfront bool, cfg aws.Config, regions []string) (*methodaws.WafReport, error) {
	// Initialize Struct
	report := methodaws.WafReport{}
	var regionReports []*methodaws.RegionWafInfo
	var allErrors []string

	// Set Scope and handle CloudFront WAFs region (must us "us-east-1")
	scope := types.ScopeRegional
	if cloudfront {
		scope = types.ScopeCloudfront
		regions = []string{"us-east-1"}
	}

	for _, region := range regions {
		regionCfg := cfg.Copy()
		regionCfg.Region = region

		wafClient := wafv2.NewFromConfig(regionCfg)
		listWebACLsInput := &wafv2.ListWebACLsInput{Scope: scope}
		webACLsOutput, err := wafClient.ListWebACLs(ctx, listWebACLsInput)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		var wafs []*methodaws.Waf
		for _, webACL := range webACLsOutput.WebACLs {
			// Get Rules
			rules, err := getRules(ctx, wafClient, scope, webACL.Id, webACL.Name)
			if err != nil {
				allErrors = append(allErrors, err.Error())
				continue
			}

			// Get Resources
			resources, err := getResources(ctx, wafClient, webACL.ARN, scope)
			if err != nil {
				allErrors = append(allErrors, err.Error())
				continue
			}

			// Marshal WAF data
			description := aws.ToString(webACL.Description)
			waf := methodaws.Waf{
				Arn:         aws.ToString(webACL.ARN),
				Name:        aws.ToString(webACL.Name),
				Description: &description,
				Rules:       rules,
				Resources:   resources,
			}
			wafs = append(wafs, &waf)
		}

		// Marshal regional
		setRegion := region
		if cloudfront {
			setRegion = "all"
		}
		regionReport := methodaws.RegionWafInfo{
			Region: setRegion,
			Wafs:   wafs,
		}
		regionReports = append(regionReports, &regionReport)
	}

	// Finalize report
	report.Scope = methodaws.ScopeTypeRegional
	if cloudfront {
		report.Scope = methodaws.ScopeTypeCloudfront
	}
	report.Regions = regionReports
	report.Errors = allErrors
	return &report, nil
}

func getRules(ctx context.Context, wafClient *wafv2.Client, scope types.Scope, webACLId, webACLName *string) ([]*methodaws.RuleInfo, error) {
	getWebACLInput := &wafv2.GetWebACLInput{Id: webACLId, Name: webACLName, Scope: scope}
	webACLOutput, err := wafClient.GetWebACL(ctx, getWebACLInput)
	if err != nil {
		return nil, err
	}

	var rules []*methodaws.RuleInfo
	for _, rule := range webACLOutput.WebACL.Rules {
		ruleInfo := methodaws.RuleInfo{
			Name:     aws.ToString(rule.Name),
			Priority: int(rule.Priority),
		}
		rules = append(rules, &ruleInfo)
	}
	return rules, nil
}

func getResources(ctx context.Context, wafClient *wafv2.Client, webACLArn *string, scope types.Scope) ([]*methodaws.ResourceInfo, error) {
	// Only list resources for regional WAFs (CloudFront does not support ListResourcesForWebACL)
	if scope == types.ScopeCloudfront {
		return []*methodaws.ResourceInfo{}, nil
	}

	listResourcesInput := &wafv2.ListResourcesForWebACLInput{WebACLArn: webACLArn}
	listResourcesOutput, err := wafClient.ListResourcesForWebACL(ctx, listResourcesInput)
	if err != nil {
		return nil, err
	}

	var resourceInfos []*methodaws.ResourceInfo
	for _, arn := range listResourcesOutput.ResourceArns {
		resourceInfo := methodaws.ResourceInfo{
			Arn: arn,
		}
		resourceInfos = append(resourceInfos, &resourceInfo)
	}
	return resourceInfos, nil
}
