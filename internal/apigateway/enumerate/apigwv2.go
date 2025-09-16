package apigateway

import (
	"context"
	"fmt"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV2ApiGatewaysAllRegions enumerates v2 API Gateways (HTTP APIs) across all specified regions
func enumerateV2ApiGatewaysAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v2 API Gateways in region", svc1log.SafeParam("region", region))
		apiGateways, errors := enumerateV2ApiGatewaysForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v2 API Gateways in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allAPIGateways = append(allAPIGateways, apiGateways...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v2 API Gateways in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("apiGatewayCount", len(apiGateways)))
	}

	return allAPIGateways, allErrors
}

// enumerateV2ApiGatewaysForRegion enumerates v2 API Gateways (HTTP APIs) for a specific region
func enumerateV2ApiGatewaysForRegion(ctx context.Context, cfg aws.Config, region string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	client := apigatewayv2.NewFromConfig(regionCfg)

	var apiGateways []*apigatewayfern.ApiGatewayInstance
	var errors []string

	// Manual pagination since GetApis doesn't have a built-in paginator
	var nextToken *string
	for {
		input := &apigatewayv2.GetApisInput{
			NextToken: nextToken,
		}

		result, err := client.GetApis(ctx, input)
		if err != nil {
			log.Warn("Failed to retrieve HTTP APIs",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Failed to retrieve HTTP APIs in region %s: %s", region, err.Error()))
			break
		}

		// Process APIs sequentially
		for _, api := range result.Items {
			if api.ApiId == nil {
				log.Warn("HTTP API ID is nil", svc1log.SafeParam("api", api))
				errors = append(errors, "HTTP API ID is nil")
				continue
			}
			apiGw, errs := convertV2HttpAPIToFern(ctx, client, api, region)

			if apiGw != nil {
				apiGateways = append(apiGateways, apiGw)
			}
			errors = append(errors, errs...)
		}

		// Check if there are more pages
		if result.NextToken == nil {
			break
		}
		nextToken = result.NextToken
	}

	return apiGateways, errors
}

// convertV2HttpAPIToFern converts AWS HTTP API to Fern ApiGatewayInstance struct
func convertV2HttpAPIToFern(ctx context.Context, client *apigatewayv2.Client, api types.Api, region string) (*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)

	var errors []string

	if api.ApiId == nil {
		log.Warn("API Gateway API ID is nil", svc1log.SafeParam("apiId", *api.ApiId))
		errors = append(errors, "api gateway API ID is nil")
		return nil, errors
	}

	// Get routes for this API with security info
	routes, errs := getHTTPAPIRoutes(ctx, client, *api.ApiId, region)
	errors = append(errors, errs...)

	// Convert CORS configuration
	var corsConfig *apigatewayfern.CorsConfiguration
	if api.CorsConfiguration != nil {
		corsConfig = &apigatewayfern.CorsConfiguration{
			AllowCredentials: api.CorsConfiguration.AllowCredentials,
			MaxAge:           convertInt32PtrToIntPtr(api.CorsConfiguration.MaxAge),
		}

		if api.CorsConfiguration.AllowHeaders != nil {
			corsConfig.AllowHeaders = api.CorsConfiguration.AllowHeaders
		}
		if api.CorsConfiguration.AllowMethods != nil {
			corsConfig.AllowMethods = api.CorsConfiguration.AllowMethods
		}
		if api.CorsConfiguration.AllowOrigins != nil {
			corsConfig.AllowOrigins = api.CorsConfiguration.AllowOrigins
		}
		if api.CorsConfiguration.ExposeHeaders != nil {
			corsConfig.ExposeHeaders = api.CorsConfiguration.ExposeHeaders
		}
	}

	// Get domain name certificates (similar to v1 but for HTTP API)
	certificates, errs := getHTTPAPICertificates(ctx, client, *api.ApiId)
	errors = append(errors, errs...)

	// Get stages for this API
	stages, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{
		ApiId: api.ApiId,
	})
	var primaryStageName *string
	if err != nil {
		errors = append(errors, err.Error())
	} else if len(stages.Items) > 0 {
		// Use the first non-$default stage found
		for _, stage := range stages.Items {
			if stage.StageName != nil && *stage.StageName != "$default" {
				primaryStageName = stage.StageName
				break
			}
		}
	}

	// Get access log settings
	accessLogSettings, err := getHTTPAPIAccessLogSettings(ctx, client, *api.ApiId)
	if err != nil {
		errors = append(errors, err.Error())
	}
	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, corsConfig, nil) // V2 doesn't use API keys the same way

	var apiEndpoint string
	if api.ApiEndpoint != nil {
		apiEndpoint = *api.ApiEndpoint
	}

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Id:     *api.ApiId,
		Name:   api.Name,
		Region: region,
		Url:    apiEndpoint,
	}

	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:           apigatewayfern.ApiGatewayVersionV2,
		Description:       api.Description,
		Stage:             primaryStageName,
		AccessLogSettings: accessLogSettings,
		CorsConfiguration: corsConfig,
		Certificates:      certificates,
		Security:          securityAnalysis,
	}

	// Create resource info
	resources := &apigatewayfern.ApiGatewayResourceInfo{
		Routes: routes,
	}

	// Create ApiGatewayInstance
	apiGatewayInstance := &apigatewayfern.ApiGatewayInstance{
		Identification: identification,
		Configuration:  configuration,
		Resources:      resources,
	}

	return apiGatewayInstance, errors
}

// getHTTPAPIRoutes retrieves routes for an HTTP API
func getHTTPAPIRoutes(ctx context.Context, client *apigatewayv2.Client, apiID, region string) ([]*apigatewayfern.Route, []string) {
	var routes []*apigatewayfern.Route
	var errors []string

	// Get routes for the API
	routesResult, err := client.GetRoutes(ctx, &apigatewayv2.GetRoutesInput{ApiId: &apiID})
	if err != nil {
		return routes, []string{err.Error()}
	}

	for _, route := range routesResult.Items {
		// Get integration for this route if it exists
		var integration *apigatewayfern.Integration
		if route.Target != nil {
			// Extract integration ID from target (format: "integrations/{integrationId}")
			if len(*route.Target) > len("integrations/") {
				integrationID := (*route.Target)[len("integrations/"):]
				integrationResult, err := client.GetIntegration(ctx, &apigatewayv2.GetIntegrationInput{
					ApiId:         &apiID,
					IntegrationId: &integrationID,
				})
				if err != nil {
					errors = append(errors, err.Error())
				} else {
					integ, err := convertV2Integration(integrationResult, region)
					if err != nil {
						errors = append(errors, err.Error())
					} else {
						integration = integ
					}
				}
			}
		}

		// Parse method and path from route key (e.g., "GET /users/{id}")
		routeKey := *route.RouteKey
		method := ""
		path := routeKey

		parts := strings.SplitN(routeKey, " ", 2)
		if len(parts) == 2 {
			method = parts[0]
			path = parts[1]
		}

		// Get authorization information
		var authType *apigatewayfern.AuthorizationType
		if route.AuthorizationType != "" {
			switch route.AuthorizationType {
			case types.AuthorizationTypeNone:
				authTypeValue := apigatewayfern.AuthorizationTypeNone
				authType = &authTypeValue
			case types.AuthorizationTypeAwsIam:
				authTypeValue := apigatewayfern.AuthorizationTypeAwsIam
				authType = &authTypeValue
			case types.AuthorizationTypeJwt:
				authTypeValue := apigatewayfern.AuthorizationTypeJwt
				authType = &authTypeValue
			}
		}

		// Get authorizer details if specified (simplified - not included in route)
		_ = route.AuthorizerId

		// Create route-specific resource links
		resourceLinks := createRouteResources(integration, region)

		// Create resources with integration and other links
		resources := &apigatewayfern.RouteResourceInfo{
			Integration: integration,
		}

		// Add other resource links if they exist
		if resourceLinks != nil {
			resources.ExecutionRole = resourceLinks.ExecutionRole
			resources.CloudWatchLog = resourceLinks.CloudWatchLog
		}

		fernRoute := &apigatewayfern.Route{
			Identification: &apigatewayfern.RouteIdentificationInfo{
				Path:   path,
				Method: method,
			},
			Configuration: &apigatewayfern.RouteConfigurationInfo{
				Authorization: authType,
				// Note: HTTP API doesn't have API key requirement per route like REST API
			},
			Resources: resources,
		}

		routes = append(routes, fernRoute)
	}

	return routes, errors
}

// convertV2Integration converts AWS API Gateway v2 integration to Fern Integration with backend structure
func convertV2Integration(integration *apigatewayv2.GetIntegrationOutput, region string) (*apigatewayfern.Integration, error) {
	switch integration.IntegrationType {
	case types.IntegrationTypeHttp:
		uri := aws.ToString(integration.IntegrationUri)

		// Check if this is a VPC Link integration (private load balancer)
		if integration.ConnectionType == types.ConnectionTypeVpcLink &&
			integration.ConnectionId != nil {
			backend := createV2LoadBalancerBackend(integration, region)
			return apigatewayfern.NewIntegrationFromVpcLink(&apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}), nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        uri,
			IsExternal: !strings.Contains(uri, ".amazonaws.com"),
		}

		return apigatewayfern.NewIntegrationFromHttp(&apigatewayfern.HttpIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeAws:
		arn := aws.ToString(integration.IntegrationUri)
		backend := &apigatewayfern.AwsServiceBackend{
			Arn:     arn,
			Service: extractServiceFromArn(arn),
			Region:  region,
		}

		return apigatewayfern.NewIntegrationFromAws(&apigatewayfern.AwsIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeHttpProxy:
		uri := aws.ToString(integration.IntegrationUri)

		// Check if this is a VPC Link integration (private load balancer)
		if integration.ConnectionType == types.ConnectionTypeVpcLink &&
			integration.ConnectionId != nil {
			backend := createV2LoadBalancerBackend(integration, region)
			return apigatewayfern.NewIntegrationFromVpcLink(&apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}), nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        uri,
			IsExternal: !strings.Contains(uri, ".amazonaws.com"),
		}

		return apigatewayfern.NewIntegrationFromHttpProxy(&apigatewayfern.HttpProxyIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeAwsProxy:
		arn := aws.ToString(integration.IntegrationUri)
		backend := &apigatewayfern.LambdaBackend{
			Arn:          arn,
			FunctionName: extractResourceNameFromArn(arn),
			Region:       region,
		}

		return apigatewayfern.NewIntegrationFromAwsProxy(&apigatewayfern.AwsProxyIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeMock:
		backend := &apigatewayfern.MockBackend{}
		return apigatewayfern.NewIntegrationFromMock(&apigatewayfern.MockIntegration{
			Backend: backend,
		}), nil

	default:
		return nil, fmt.Errorf("unsupported integration type: %s", integration.IntegrationType)
	}
}

// createV2LoadBalancerBackend creates a LoadBalancerBackend from V2 integration details
func createV2LoadBalancerBackend(integration *apigatewayv2.GetIntegrationOutput, region string) *apigatewayfern.LoadBalancerBackend {
	uri := aws.ToString(integration.IntegrationUri)
	connectionID := aws.ToString(integration.ConnectionId)

	// Extract DNS name from URI
	dnsName := extractDNSNameFromURI(uri)

	return &apigatewayfern.LoadBalancerBackend{
		Uri:             uri,
		VpcLinkId:       connectionID,
		LoadBalancerArn: "", // Would need additional API call to get actual ARN
		DnsName:         &dnsName,
	}
}

// getHTTPAPICertificates retrieves certificates for an HTTP API
func getHTTPAPICertificates(ctx context.Context, client *apigatewayv2.Client, apiID string) ([]*apigatewayfern.Certificate, []string) {
	var certificates []*apigatewayfern.Certificate
	var errors []string

	// Get domain names for this API
	domainNames, err := client.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{})
	if err != nil {
		return certificates, []string{err.Error()}
	}

	for _, domain := range domainNames.Items {
		// Check if this domain is associated with our API
		mappings, err := client.GetApiMappings(ctx, &apigatewayv2.GetApiMappingsInput{
			DomainName: domain.DomainName,
		})
		if err != nil {
			continue
		}

		// Check if any mapping is for our API
		for _, mapping := range mappings.Items {
			if mapping.ApiId != nil && *mapping.ApiId == apiID {
				cert := &apigatewayfern.Certificate{
					Arn:        *domain.DomainNameConfigurations[0].CertificateArn,
					DomainName: domain.DomainName,
				}

				// Convert security policy
				if len(domain.DomainNameConfigurations) > 0 && domain.DomainNameConfigurations[0].SecurityPolicy != "" {
					switch domain.DomainNameConfigurations[0].SecurityPolicy {
					case types.SecurityPolicyTls10:
						policy := apigatewayfern.SecurityPolicyTls10
						cert.SecurityPolicy = &policy
					case types.SecurityPolicyTls12:
						policy := apigatewayfern.SecurityPolicyTls12
						cert.SecurityPolicy = &policy
					}
				}

				certificates = append(certificates, cert)
				break
			}
		}
	}

	return certificates, errors
}

// getHTTPAPIAccessLogSettings retrieves access log configuration
func getHTTPAPIAccessLogSettings(ctx context.Context, client *apigatewayv2.Client, apiID string) (*apigatewayfern.AccessLogSettings, error) {
	// Get stages for this API to find access log settings
	stages, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{
		ApiId: &apiID,
	})
	if err != nil {
		return nil, err
	}

	// Look for access log settings in any stage (typically $default)
	for _, stage := range stages.Items {
		if stage.AccessLogSettings != nil && stage.AccessLogSettings.DestinationArn != nil {
			return &apigatewayfern.AccessLogSettings{
				DestinationArn: *stage.AccessLogSettings.DestinationArn,
				Format:         stage.AccessLogSettings.Format,
			}, nil
		}
	}

	return nil, nil
}
