package iam

import (
	"context"

	iam "github.com/Method-Security/methodaws/generated/go/iam"
	"github.com/aws/aws-sdk-go-v2/aws"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateIam enumerates IAM resources based on the provided configuration
func EnumerateIam(ctx context.Context, awsConfig aws.Config, config iam.IamEnumerateConfig) *iam.IamEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting IAM enumeration",
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &iam.IamEnumerateReport{
		Config: &config,
		Result: &iam.IamEnumerateResult{
			Resources: &iam.IamResources{},
		},
	}

	var allErrors []string

	// Enumerate roles
	log.Info("Enumerating IAM roles")
	roles, rolesErrors := enumerateIamRoles(ctx, awsConfig)
	allErrors = append(allErrors, rolesErrors...)

	// Enumerate policies
	log.Info("Enumerating IAM policies")
	policyReport, policiesErrors := enumerateIamPolicies(ctx, awsConfig)
	allErrors = append(allErrors, policiesErrors...)

	// Populate report
	report.Result.Resources.Roles = roles
	report.Result.Resources.Policies = policyReport

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed IAM enumeration",
		svc1log.SafeParam("totalRoles", len(roles)),
		svc1log.SafeParam("totalPolicies", len(policyReport.Policies)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}
