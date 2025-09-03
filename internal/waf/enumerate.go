// Package waf provides functionality to enumerate and integrate AWS WAF resources.
package waf

import (
	"context"
	"encoding/json"
	"strings"

	waffern "github.com/Method-Security/methodaws/generated/go/waf"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func EnumerateWAF(ctx context.Context, awsConfig aws.Config, config waffern.WafEnumerateConfig) *waffern.WafEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting WAF enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &waffern.WafEnumerateReport{
		Config: &config,
		Result: &waffern.WafEnumerateResult{},
	}

	var regionReports []*waffern.RegionWafInfo
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing WAF instances in region", svc1log.SafeParam("region", region))
		wafs, errors := enumerateWAFForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating WAF instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allErrors = append(allErrors, errors...)

		regionReport := waffern.RegionWafInfo{
			Region: region,
			Wafs:   wafs,
		}
		// Only add region report if there are WAFs in the region
		if len(wafs) > 0 {
			regionReports = append(regionReports, &regionReport)
		}
		log.Info("Successfully processed WAF instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("wafCount", len(wafs)))
	}

	// Marshal report
	report.Result.Scope = waffern.ScopeTypeRegional
	if len(regionReports) > 0 {
		report.Result.Regions = regionReports
	}
	report.Errors = allErrors
	return report
}

func enumerateWAFForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*waffern.Waf, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	wafClient := wafv2.NewFromConfig(awsConfig)
	var errors []string

	// List WAF WebACLs
	listWebACLsInput := &wafv2.ListWebACLsInput{Scope: types.ScopeRegional}
	webACLsOutput, err := wafClient.ListWebACLs(ctx, listWebACLsInput)
	if err != nil {
		errorMsg := "Failed to list WAF WebACLs in region " + region + ": " + err.Error()
		log.Error("Error listing WAF WebACLs", svc1log.SafeParam("error", err.Error()))
		errors = append(errors, errorMsg)
		return nil, errors
	}

	log.Info("Successfully listed WAF WebACLs", svc1log.SafeParam("count", len(webACLsOutput.WebACLs)))

	var wafs []*waffern.Waf
	for _, webACL := range webACLsOutput.WebACLs {
		rules, defaultAction, errs := getRules(ctx, wafClient, types.ScopeRegional, webACL.Id, webACL.Name)
		if len(errs) != 0 {
			errors = append(errors, errs...)
			continue
		}

		resources, err := getResources(ctx, wafClient, webACL.ARN)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		description := aws.ToString(webACL.Description)
		waf := waffern.Waf{
			Arn:           aws.ToString(webACL.ARN),
			Name:          aws.ToString(webACL.Name),
			Description:   &description,
			DefaultAction: *defaultAction,
			Rules:         rules,
			Resources:     resources,
		}
		wafs = append(wafs, &waf)
	}

	return wafs, errors
}

func getRules(ctx context.Context, wafClient *wafv2.Client, scope types.Scope, webACLId, webACLName *string) ([]*waffern.RuleInfo, *waffern.ActionType, []string) {
	getWebACLInput := &wafv2.GetWebACLInput{Id: webACLId, Name: webACLName, Scope: scope}
	webACLOutput, err := wafClient.GetWebACL(ctx, getWebACLInput)
	if err != nil {
		return nil, nil, []string{err.Error()}
	}

	// Default Action
	defaultAction := webACLOutput.WebACL.DefaultAction
	if defaultAction == nil {
		return nil, nil, []string{"no default action specified"}
	}
	defaultActionType := getDefaultActionType(defaultAction)

	var rules []*waffern.RuleInfo
	var errors []string
	for _, rule := range webACLOutput.WebACL.Rules {
		ruleJSON, err := json.Marshal(rule)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		statementJSON, err := json.Marshal(rule.Statement)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		var actionJSONString *string
		var actionInfo *waffern.ActionInfo

		if rule.Action != nil {
			actionJSON, err := json.Marshal(rule.Action)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			actionJSONStr := string(actionJSON)
			actionJSONString = &actionJSONStr
			actionInfo = &waffern.ActionInfo{
				Type:       getActionType(rule.Action),
				JsonString: actionJSONString,
			}
		}

		statementJSONString := string(statementJSON)
		ruleInfo := waffern.RuleInfo{
			Name:     aws.ToString(rule.Name),
			Priority: int(rule.Priority),
			Statement: &waffern.StatementInfo{
				Type:         getStatementType(rule.Statement),
				RawStatement: &statementJSONString,
			},
			Action:  actionInfo,
			RawRule: string(ruleJSON),
		}
		rules = append(rules, &ruleInfo)
	}

	return rules, &defaultActionType, errors
}

func getResources(ctx context.Context, wafClient *wafv2.Client, webACLArn *string) ([]*waffern.ResourceInfo, error) {
	listResourcesInput := &wafv2.ListResourcesForWebACLInput{WebACLArn: webACLArn}
	listResourcesOutput, err := wafClient.ListResourcesForWebACL(ctx, listResourcesInput)
	if err != nil {
		return nil, err
	}

	var resourceInfos []*waffern.ResourceInfo
	for _, arn := range listResourcesOutput.ResourceArns {
		resourceInfo := waffern.ResourceInfo{
			Arn:  arn,
			Type: getResourceTypeFromArn(arn),
		}
		resourceInfos = append(resourceInfos, &resourceInfo)
	}
	return resourceInfos, nil
}

func getActionType(action *types.RuleAction) waffern.ActionType {
	switch {
	case action.Allow != nil:
		return waffern.ActionTypeAllow
	case action.Block != nil:
		return waffern.ActionTypeBlock
	case action.Captcha != nil:
		return waffern.ActionTypeCaptcha
	case action.Challenge != nil:
		return waffern.ActionTypeChallenge
	case action.Count != nil:
		return waffern.ActionTypeCount
	default:
		return waffern.ActionTypeOther
	}
}

func getDefaultActionType(action *types.DefaultAction) waffern.ActionType {
	switch {
	case action.Allow != nil:
		return waffern.ActionTypeAllow
	case action.Block != nil:
		return waffern.ActionTypeBlock
	default:
		return waffern.ActionTypeOther
	}
}

func getResourceTypeFromArn(arn string) waffern.WafResourceType {
	switch {
	case strings.Contains(arn, "elasticloadbalancing") && strings.Contains(arn, "loadbalancer/app"):
		return waffern.WafResourceTypeApplicationLoadBalancer
	case strings.Contains(arn, "apigateway") && strings.Contains(arn, "/restapis/"):
		return waffern.WafResourceTypeApiGatewayRestApi
	case strings.Contains(arn, "appsync") && strings.Contains(arn, "apis"):
		return waffern.WafResourceTypeAppsyncGraphqlApi
	case strings.Contains(arn, "cognito-idp") && strings.Contains(arn, "userpool"):
		return waffern.WafResourceTypeCognitoUserPool
	case strings.Contains(arn, "apprunner") && strings.Contains(arn, "service"):
		return waffern.WafResourceTypeAppRunnerService
	case strings.Contains(arn, "verifiedaccess") && strings.Contains(arn, "instance"):
		return waffern.WafResourceTypeVerifiedAccessInstance
	default:
		return waffern.WafResourceTypeOther
	}
}

func getStatementType(statement *types.Statement) waffern.StatementType {
	switch {
	case statement.AndStatement != nil:
		return waffern.StatementTypeAnd
	case statement.ByteMatchStatement != nil:
		return waffern.StatementTypeByteMatch
	case statement.GeoMatchStatement != nil:
		return waffern.StatementTypeGeoMatch
	case statement.IPSetReferenceStatement != nil:
		return waffern.StatementTypeIpSetReference
	case statement.LabelMatchStatement != nil:
		return waffern.StatementTypeLabelMatch
	case statement.ManagedRuleGroupStatement != nil:
		return waffern.StatementTypeManagedRuleGroup
	case statement.NotStatement != nil:
		return waffern.StatementTypeNot
	case statement.OrStatement != nil:
		return waffern.StatementTypeOr
	case statement.RateBasedStatement != nil:
		return waffern.StatementTypeRateBased
	case statement.RegexMatchStatement != nil:
		return waffern.StatementTypeRegexMatch
	case statement.RegexPatternSetReferenceStatement != nil:
		return waffern.StatementTypeRegexPatternsetRefence
	case statement.RuleGroupReferenceStatement != nil:
		return waffern.StatementTypeRuleGroupReference
	case statement.SizeConstraintStatement != nil:
		return waffern.StatementTypeSizeConstraint
	case statement.SqliMatchStatement != nil:
		return waffern.StatementTypeSqliMatch
	case statement.XssMatchStatement != nil:
		return waffern.StatementTypeXssMatch
	default:
		return waffern.StatementTypeOther
	}
}
