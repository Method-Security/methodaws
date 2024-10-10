package waf

import (
	"context"
	"encoding/json"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

func EnumerateWAF(ctx context.Context, cfg aws.Config, regions []string) (*methodaws.WafReport, error) {
	// Initialize Struct
	report := methodaws.WafReport{}
	var regionReports []*methodaws.RegionWafInfo
	var allErrors []string

	for _, region := range regions {
		regionCfg := cfg.Copy()
		regionCfg.Region = region

		wafClient := wafv2.NewFromConfig(regionCfg)
		listWebACLsInput := &wafv2.ListWebACLsInput{Scope: types.ScopeRegional}
		webACLsOutput, err := wafClient.ListWebACLs(ctx, listWebACLsInput)
		if err != nil {
			allErrors = append(allErrors, err.Error())
			continue
		}

		var wafs []*methodaws.Waf
		for _, webACL := range webACLsOutput.WebACLs {
			// Get Rules
			rules, errs := getRules(ctx, wafClient, types.ScopeRegional, webACL.Id, webACL.Name)
			if len(errs) != 0 {
				allErrors = append(allErrors, errs...)
				continue
			}

			// Get Resources
			resources, err := getResources(ctx, wafClient, webACL.ARN)
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

		// Marshal Regional Report
		setRegion := region
		regionReport := methodaws.RegionWafInfo{
			Region: setRegion,
			Wafs:   wafs,
		}
		regionReports = append(regionReports, &regionReport)
	}

	// Marshal Report
	report.Scope = methodaws.ScopeTypeRegional
	report.Regions = regionReports
	report.Errors = allErrors
	return &report, nil
}

func getRules(ctx context.Context, wafClient *wafv2.Client, scope types.Scope, webACLId, webACLName *string) ([]*methodaws.RuleInfo, []string) {
	getWebACLInput := &wafv2.GetWebACLInput{Id: webACLId, Name: webACLName, Scope: scope}
	webACLOutput, err := wafClient.GetWebACL(ctx, getWebACLInput)
	if err != nil {
		return nil, []string{err.Error()}
	}

	var rules []*methodaws.RuleInfo
	var errors []string
	for _, rule := range webACLOutput.WebACL.Rules {
		ruleJSON, err := json.Marshal(rule)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		ruleInfo := methodaws.RuleInfo{
			Name:     aws.ToString(rule.Name),
			Priority: int(rule.Priority),
			JsonBlob: string(ruleJSON),
		}
		rules = append(rules, &ruleInfo)
	}
	return rules, errors
}

func getResources(ctx context.Context, wafClient *wafv2.Client, webACLArn *string) ([]*methodaws.ResourceInfo, error) {
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
