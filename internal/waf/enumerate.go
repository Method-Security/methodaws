// Package waf provides functionality to enumerate and integrate AWS WAF resources.
package waf

import (
	"context"
	"encoding/json"
	"strings"

	common "github.com/Method-Security/methodaws/generated/go/common"
	waffern "github.com/Method-Security/methodaws/generated/go/waf"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateWAF enumerates WAFs based on the provided configuration
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

	var allErrors []string
	var allWafs []*waffern.WafInstance
	for _, region := range config.Regions {
		log.Info("Processing WAF instances in region", svc1log.SafeParam("region", region))
		wafs, errors := enumerateWAFForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating WAF instances in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allErrors = append(allErrors, errors...)
		allWafs = append(allWafs, wafs...)

		log.Info("Successfully processed WAF instances in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("wafCount", len(wafs)))
	}

	// Set the results
	if len(allWafs) > 0 {
		report.Result.Wafs = allWafs
	}
	report.Errors = allErrors
	return report
}

// enumerateWAFForRegion enumerates WAFs for a given region
func enumerateWAFForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*waffern.WafInstance, []string) {
	log := svc1log.FromContext(ctx)
	awsConfig.Region = region

	wafClient := wafv2.NewFromConfig(awsConfig)
	var errors []string

	// List WAF WebACLs with pagination
	var allWebACLs []types.WebACLSummary
	var nextMarker *string
	for {
		listWebACLsInput := &wafv2.ListWebACLsInput{
			Scope:      types.ScopeRegional,
			NextMarker: nextMarker,
		}
		webACLsOutput, err := wafClient.ListWebACLs(ctx, listWebACLsInput)
		if err != nil {
			errorMsg := "Failed to list WAF WebACLs in region " + region + ": " + err.Error()
			log.Error("Error listing WAF WebACLs", svc1log.SafeParam("error", err.Error()))
			errors = append(errors, errorMsg)
			break
		}
		allWebACLs = append(allWebACLs, webACLsOutput.WebACLs...)
		if webACLsOutput.NextMarker == nil {
			break
		}
		nextMarker = webACLsOutput.NextMarker
	}

	log.Info("Successfully listed WAF WebACLs", svc1log.SafeParam("count", len(allWebACLs)))

	var wafs []*waffern.WafInstance
	for _, webACL := range allWebACLs {
		// check if WAF has an ID
		if webACL.ARN == nil {
			log.Warn("WAF WebACL ARN is nil", svc1log.SafeParam("webACL", webACL))
			errors = append(errors, "WAF WebACL ARN is nil")
			continue
		}

		// Get the rules for the WAF
		rules, defaultAction, errs := getRules(ctx, wafClient, types.ScopeRegional, webACL.Id, webACL.Name)
		if len(errs) != 0 {
			errors = append(errors, errs...)
			continue
		}

		// Get the resources for the WAF
		resourceInfo := &waffern.WafResourceInfo{
			Rules: rules,
		}

		// Add resource discovery from fronted resources
		if lbRef := discoverLoadBalancerFromWebACL(ctx, wafClient, webACL.ARN, region); lbRef != nil {
			resourceInfo.LoadBalancer = lbRef
		}
		if apiRef := discoverAPIGatewayFromWebACL(ctx, wafClient, webACL.ARN, region); apiRef != nil {
			resourceInfo.ApiGateway = apiRef
		}

		waf := waffern.WafInstance{
			Identification: &waffern.WafIdentificationInfo{
				Arn:    aws.ToString(webACL.ARN),
				Name:   webACL.Name,
				Region: region,
			},
			Configuration: &waffern.WafConfigurationInfo{
				Scope:         waffern.ScopeTypeRegional,
				Description:   webACL.Description,
				DefaultAction: defaultAction,
			},
			Resources: resourceInfo,
		}
		wafs = append(wafs, &waf)
	}

	return wafs, errors
}

// getRules gets the rules for a given WebACL
func getRules(ctx context.Context, wafClient *wafv2.Client, scope types.Scope, webACLId, webACLName *string) ([]*waffern.RuleInfo, *waffern.ActionType, []string) {
	log := svc1log.FromContext(ctx)
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
		if rule.Name == nil {
			log.Warn("WAF Rule Name is nil", svc1log.SafeParam("rule", rule))
			errors = append(errors, "WAF Rule Name is nil")
			continue
		}
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
			Identification: &waffern.RuleIdentificationInfo{
				Name: aws.ToString(rule.Name),
			},
			Configuration: &waffern.RuleConfigurationInfo{
				Priority: int(rule.Priority),
				Statement: &waffern.StatementInfo{
					Type:         getStatementType(rule.Statement),
					RawStatement: &statementJSONString,
				},
				Action:  actionInfo,
				RawRule: string(ruleJSON),
			},
		}
		rules = append(rules, &ruleInfo)
	}

	return rules, &defaultActionType, errors
}

// getActionType gets the action type for a given RuleAction
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

// getDefaultActionType gets the default action type for a given DefaultAction
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

// getStatementType gets the statement type for a given Statement
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

// Resource discovery functions
func discoverLoadBalancerFromWebACL(ctx context.Context, wafClient *wafv2.Client, webACLArn *string, region string) *common.LoadBalancerReference {
	log := svc1log.FromContext(ctx)
	listResourcesInput := &wafv2.ListResourcesForWebACLInput{WebACLArn: webACLArn}
	listResourcesOutput, err := wafClient.ListResourcesForWebACL(ctx, listResourcesInput)
	if err != nil {
		log.Warn("Failed to list resources for WebACL (LB discovery)",
			svc1log.SafeParam("webACLArn", aws.ToString(webACLArn)),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return nil
	}

	for _, arn := range listResourcesOutput.ResourceArns {
		if strings.Contains(arn, "elasticloadbalancing") && strings.Contains(arn, "loadbalancer/app") {
			// Extract load balancer name from ARN
			lbName := extractLoadBalancerNameFromArn(arn)
			lbType := common.LoadBalancerTypeApplication

			if lbName != "" {
				dnsName := ""
				return &common.LoadBalancerReference{
					Arn:     arn,
					DnsName: &dnsName,
					Region:  region,
					Type:    lbType,
				}
			}
		}
	}
	return nil
}

// discoverAPIGatewayFromWebACL discovers the API Gateway from the WebACL
func discoverAPIGatewayFromWebACL(ctx context.Context, wafClient *wafv2.Client, webACLArn *string, region string) *common.ApiGatewayReference {
	log := svc1log.FromContext(ctx)
	listResourcesInput := &wafv2.ListResourcesForWebACLInput{WebACLArn: webACLArn}
	listResourcesOutput, err := wafClient.ListResourcesForWebACL(ctx, listResourcesInput)
	if err != nil {
		log.Warn("Failed to list resources for WebACL (API GW discovery)",
			svc1log.SafeParam("webACLArn", aws.ToString(webACLArn)),
			svc1log.SafeParam("region", region),
			svc1log.Stacktrace(err))
		return nil
	}

	for _, arn := range listResourcesOutput.ResourceArns {
		if strings.Contains(arn, "apigateway") && strings.Contains(arn, "/restapis/") {
			// Extract API Gateway ID from ARN
			apiID := extractAPIGatewayIDFromArn(arn)

			if apiID != "" {
				return &common.ApiGatewayReference{
					Arn:    arn,
					ApiId:  &apiID,
					Region: region,
					Name:   nil,
				}
			}
		}
	}
	return nil
}

// Helper functions to extract resource identifiers from ARNs
func extractLoadBalancerNameFromArn(arn string) string {
	// Format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
	parts := strings.Split(arn, "/")
	if len(parts) >= 3 && parts[1] == "app" {
		return parts[2]
	}
	return ""
}

func extractAPIGatewayIDFromArn(arn string) string {
	// Format: arn:aws:apigateway:region::/restapis/api-id
	parts := strings.Split(arn, "/")
	if len(parts) >= 2 && parts[len(parts)-2] == "restapis" {
		return parts[len(parts)-1]
	}
	return ""
}
