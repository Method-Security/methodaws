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
			rules, errs := getRules(ctx, wafClient, types.ScopeRegional, webACL.Id, webACL.Name)
			if len(errs) != 0 {
				allErrors = append(allErrors, errs...)
				continue
			}

			resources, err := getResources(ctx, wafClient, webACL.ARN)
			if err != nil {
				allErrors = append(allErrors, err.Error())
				continue
			}

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

		setRegion := region
		regionReport := methodaws.RegionWafInfo{
			Region: setRegion,
			Wafs:   wafs,
		}
		regionReports = append(regionReports, &regionReport)
	}

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

		statementJSON, err := json.Marshal(rule.Statement)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		var actionJSONString *string
		var actionInfo *methodaws.ActionInfo

		if rule.Action != nil {
			actionJSON, err := json.Marshal(rule.Action)
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}
			actionJSONStr := string(actionJSON)
			actionJSONString = &actionJSONStr
			actionInfo = &methodaws.ActionInfo{
				Type:       getActionType(rule.Action),
				JsonString: actionJSONString,
			}
		}

		// Process nested statements if the rule statement is an AND, OR, or NOT statement
		nestedStatements := getNestedStatements(rule.Statement)

		statementJSONString := string(statementJSON)
		ruleInfo := methodaws.RuleInfo{
			Name:     aws.ToString(rule.Name),
			Priority: int(rule.Priority),
			Statement: &methodaws.StatementInfo{
				Type:             getStatementType(rule.Statement),
				NestedStatements: nestedStatements,
				JsonString:       &statementJSONString,
			},
			Action:     actionInfo,
			JsonString: string(ruleJSON),
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

func getActionType(action *types.RuleAction) methodaws.ActionType {
	switch {
	case action.Allow != nil:
		return methodaws.ActionTypeAllow
	case action.Block != nil:
		return methodaws.ActionTypeBlock
	case action.Captcha != nil:
		return methodaws.ActionTypeCaptcha
	case action.Challenge != nil:
		return methodaws.ActionTypeChallenge
	case action.Count != nil:
		return methodaws.ActionTypeCount
	default:
		return methodaws.ActionTypeOther
	}
}

func getNestedStatements(statement *types.Statement) []methodaws.StatementType {
	var nestedStatements []methodaws.StatementType

	switch {
	case statement.AndStatement != nil:
		for _, nestedStatement := range statement.AndStatement.Statements {
			nestedStatements = append(nestedStatements, getStatementType(&nestedStatement))
		}
	case statement.OrStatement != nil:
		for _, nestedStatement := range statement.OrStatement.Statements {
			nestedStatements = append(nestedStatements, getStatementType(&nestedStatement))
		}
	case statement.NotStatement != nil:
		nestedStatements = append(nestedStatements, getStatementType(statement.NotStatement.Statement))
	}

	return nestedStatements
}

func getStatementType(statement *types.Statement) methodaws.StatementType {
	switch {
	case statement.AndStatement != nil:
		return methodaws.StatementTypeAnd
	case statement.ByteMatchStatement != nil:
		return methodaws.StatementTypeByteMatch
	case statement.GeoMatchStatement != nil:
		return methodaws.StatementTypeGeoMatch
	case statement.IPSetReferenceStatement != nil:
		return methodaws.StatementTypeIpSetReference
	case statement.LabelMatchStatement != nil:
		return methodaws.StatementTypeLabelMatch
	case statement.ManagedRuleGroupStatement != nil:
		return methodaws.StatementTypeManagedRuleGroup
	case statement.NotStatement != nil:
		return methodaws.StatementTypeNot
	case statement.OrStatement != nil:
		return methodaws.StatementTypeOr
	case statement.RateBasedStatement != nil:
		return methodaws.StatementTypeRateBased
	case statement.RegexMatchStatement != nil:
		return methodaws.StatementTypeRegexMatch
	case statement.RegexPatternSetReferenceStatement != nil:
		return methodaws.StatementTypeRegexPatternsetRefence
	case statement.RuleGroupReferenceStatement != nil:
		return methodaws.StatementTypeRuleGroupReference
	case statement.SizeConstraintStatement != nil:
		return methodaws.StatementTypeSizeConstraint
	case statement.SqliMatchStatement != nil:
		return methodaws.StatementTypeSqliMatch
	case statement.XssMatchStatement != nil:
		return methodaws.StatementTypeXssMatch
	default:
		return methodaws.StatementTypeOther
	}
}
