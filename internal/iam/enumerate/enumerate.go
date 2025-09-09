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

	// Enumerate roles (with nested policy information)
	log.Info("Enumerating IAM roles with attached policies")
	roles, rolesErrors := enumerateIamRoles(ctx, awsConfig)
	if len(rolesErrors) > 0 {
		log.Warn("Errors encountered during role enumeration",
			svc1log.SafeParam("errorCount", len(rolesErrors)))
		allErrors = append(allErrors, rolesErrors...)
	}

	// Only populate roles if we have any
	if len(roles) > 0 {
		report.Result.Resources.Roles = roles
		log.Info("Successfully enumerated IAM roles",
			svc1log.SafeParam("roleCount", len(roles)))
	} else {
		log.Info("No IAM roles found or accessible")
		// Still initialize empty slice instead of nil
		report.Result.Resources.Roles = []*iam.IamRole{}
	}

	// Add errors to report if any occurred
	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed IAM enumeration",
		svc1log.SafeParam("totalRoles", len(roles)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}
