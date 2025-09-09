package apigateway

import (
	"context"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateAPIGateway enumerates API Gateways based on the provided configuration
func EnumerateAPIGateway(ctx context.Context, awsConfig aws.Config, config apigatewayfern.ApiGatewayEnumerateConfig) *apigatewayfern.ApiGatewayEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting API Gateway enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId),
		svc1log.SafeParam("versionsCount", len(config.Versions)))

	// Initialize report
	report := &apigatewayfern.ApiGatewayEnumerateReport{
		Config: &config,
		Result: &apigatewayfern.ApiGatewayResult{},
	}

	var allAPIGateways []*apigatewayfern.ApiGateway
	var allErrors []string

	// Process each version requested
	if config.Versions != nil {
		for _, version := range config.Versions {
			switch version {
			case apigatewayfern.ApiGatewayVersionV1:
				log.Info("Processing v1 API Gateways (REST APIs)")
				v1APIs, errors := enumerateV1ApiGatewaysAllRegions(ctx, awsConfig, config.Regions)
				allAPIGateways = append(allAPIGateways, v1APIs...)
				allErrors = append(allErrors, errors...)

			case apigatewayfern.ApiGatewayVersionV2:
				log.Info("Processing v2 API Gateways (HTTP APIs)")
				v2APIs, errors := enumerateV2ApiGatewaysAllRegions(ctx, awsConfig, config.Regions)
				allAPIGateways = append(allAPIGateways, v2APIs...)
				allErrors = append(allErrors, errors...)
			}
		}
	}

	// Marshal report
	if len(allAPIGateways) > 0 {
		report.Result.Apis = allAPIGateways
	}

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed API Gateway enumeration",
		svc1log.SafeParam("totalApiGateways", len(allAPIGateways)),
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// convertInt32PtrToIntPtr converts *int32 to *int for compatibility
func convertInt32PtrToIntPtr(val *int32) *int {
	if val == nil {
		return nil
	}
	converted := int(*val)
	return &converted
}

func convertStringPtrToSlice(val *string) []string {
	if val == nil {
		return nil
	}
	return []string{*val}
}
