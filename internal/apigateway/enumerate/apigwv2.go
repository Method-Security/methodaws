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
	routes, errs := getHTTPAPIRoutes(ctx, client, *api.ApiId)
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

	// Get authorizers
	authorizers, errs := getHTTPAPIAuthorizers(ctx, client, *api.ApiId)
	errors = append(errors, errs...)

	// Get domain name certificates (similar to v1 but for HTTP API)
	certificates, errs := getHTTPAPICertificates(ctx, client, *api.ApiId)
	errors = append(errors, errs...)

	// Get access log settings
	accessLogSettings, err := getHTTPAPIAccessLogSettings(ctx, client, *api.ApiId)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Discover resource relationships
	relatedResources, lambdaFunctions, cloudwatchLogs, iamRoles, errs := discoverV2ResourceRelationships(ctx, client, *api.ApiId, routes, region)
	errors = append(errors, errs...)

	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, corsConfig, nil) // V2 doesn't use API keys the same way

	protocolType := string(api.ProtocolType)

	var apiEndpoint string
	if api.ApiEndpoint != nil {
		apiEndpoint = *api.ApiEndpoint
	}

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Id:     *api.ApiId,
		Name:   api.Name,
		Region: region,
	}

	// Create configuration info
	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:     apigatewayfern.ApiGatewayVersionV2,
		Description: api.Description,
		CreatedTime: api.CreatedDate,
		// V2 specific configuration
		ApiEndpoint:               &apiEndpoint,
		ProtocolType:              &protocolType,
		DisableExecuteApiEndpoint: api.DisableExecuteApiEndpoint,
	}

	// Create resource info
	resources := &apigatewayfern.ApiGatewayResourceInfo{
		Certificates:      certificates,
		AccessLogSettings: accessLogSettings,
		// V2 specific resources
		Routes:            routes,
		CorsConfiguration: corsConfig,
		Authorizers:       authorizers,
		// Resource relationships
		RelatedResources: relatedResources,
		LambdaFunctions:  lambdaFunctions,
		CloudwatchLogs:   cloudwatchLogs,
		IamRoles:         iamRoles,
		// Security analysis
		SecurityAnalysis: securityAnalysis,
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
func getHTTPAPIRoutes(ctx context.Context, client *apigatewayv2.Client, apiID string) ([]*apigatewayfern.Route, []string) {
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
					integ, err := convertV2Integration(integrationResult)
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
		var authorizer *apigatewayfern.Authorizer
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

		// Get authorizer details if specified
		if route.AuthorizerId != nil {
			authResult, err := client.GetAuthorizer(ctx, &apigatewayv2.GetAuthorizerInput{
				ApiId:        &apiID,
				AuthorizerId: route.AuthorizerId,
			})
			if err == nil {
				authorizer = &apigatewayfern.Authorizer{
					Id:                 *authResult.AuthorizerId,
					Name:               *authResult.Name,
					Type:               *authType,
					ResultTtlInSeconds: convertInt32PtrToIntPtr(authResult.AuthorizerResultTtlInSeconds),
				}

				// Add JWT configuration if present
				if authResult.JwtConfiguration != nil {
					if authResult.JwtConfiguration.Audience != nil {
						authorizer.ProviderArns = authResult.JwtConfiguration.Audience
					}
					if authResult.JwtConfiguration.Issuer != nil {
						authorizer.Uri = authResult.JwtConfiguration.Issuer
					}
				}
				authorizer.IdentitySource = authResult.IdentitySource
			}
		}

		fernRoute := &apigatewayfern.Route{
			Path:          path,
			Method:        method,
			Integration:   integration,
			Authorization: authType,
			Authorizer:    authorizer,
			// Note: HTTP API doesn't have API key requirement per route like REST API
		}

		routes = append(routes, fernRoute)
	}

	return routes, errors
}

// convertV2Integration converts AWS API Gateway v2 integration to Fern Integration with resource discovery
func convertV2Integration(integration *apigatewayv2.GetIntegrationOutput) (*apigatewayfern.Integration, error) {
	switch integration.IntegrationType {
	case types.IntegrationTypeHttp:
		uri := aws.ToString(integration.IntegrationUri)
		resourceRef := discoverResourceFromURI(uri)
		return apigatewayfern.NewIntegrationFromHttp(&apigatewayfern.HttpIntegration{
			Uri:               uri,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeAws:
		arn := aws.ToString(integration.IntegrationUri)
		resourceRef := discoverResourceFromArn(arn)
		return apigatewayfern.NewIntegrationFromAws(&apigatewayfern.AwsIntegration{
			Arn:               arn,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeHttpProxy:
		uri := aws.ToString(integration.IntegrationUri)
		resourceRef := discoverResourceFromURI(uri)
		return apigatewayfern.NewIntegrationFromHttpProxy(&apigatewayfern.HttpProxyIntegration{
			Uri:               uri,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeAwsProxy:
		arn := aws.ToString(integration.IntegrationUri)
		resourceRef := discoverResourceFromArn(arn)
		return apigatewayfern.NewIntegrationFromAwsProxy(&apigatewayfern.AwsProxyIntegration{
			Arn:               arn,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeMock:
		return apigatewayfern.NewIntegrationFromMock(&apigatewayfern.MockIntegration{}), nil

	default:
		return nil, fmt.Errorf("unsupported integration type: %s", integration.IntegrationType)
	}
}

// getHTTPAPIAuthorizers retrieves authorizers for an HTTP API
func getHTTPAPIAuthorizers(ctx context.Context, client *apigatewayv2.Client, apiID string) ([]*apigatewayfern.Authorizer, []string) {
	var authorizers []*apigatewayfern.Authorizer
	var errors []string

	authorizersResult, err := client.GetAuthorizers(ctx, &apigatewayv2.GetAuthorizersInput{
		ApiId: &apiID,
	})
	if err != nil {
		return authorizers, []string{err.Error()}
	}

	for _, auth := range authorizersResult.Items {
		// Convert authorization type
		var authType apigatewayfern.AuthorizationType
		switch auth.AuthorizerType {
		case types.AuthorizerTypeJwt:
			authType = apigatewayfern.AuthorizationTypeJwt
		default:
			// Skip unsupported types or log them
			svc1log.FromContext(ctx).Warn("Unsupported authorizer type",
				svc1log.SafeParam("authorizerType", auth.AuthorizerType))
			continue
		}

		authorizer := &apigatewayfern.Authorizer{
			Id:                 *auth.AuthorizerId,
			Name:               *auth.Name,
			Type:               authType,
			ResultTtlInSeconds: convertInt32PtrToIntPtr(auth.AuthorizerResultTtlInSeconds),
		}

		// Add JWT configuration details if available
		if auth.JwtConfiguration != nil {
			if auth.JwtConfiguration.Audience != nil {
				authorizer.ProviderArns = auth.JwtConfiguration.Audience
			}
			if auth.JwtConfiguration.Issuer != nil {
				authorizer.Uri = auth.JwtConfiguration.Issuer
			}
		}
		authorizer.IdentitySource = auth.IdentitySource
		authorizers = append(authorizers, authorizer)
	}

	return authorizers, errors
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
					Arn:       *domain.DomainNameConfigurations[0].CertificateArn,
					Name:      *domain.DomainName,
					IsDefault: false,
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

// discoverV2ResourceRelationships discovers related AWS resources for an HTTP API
func discoverV2ResourceRelationships(ctx context.Context, client *apigatewayv2.Client, apiID string, routes []*apigatewayfern.Route, region string) ([]*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []string) {
	var relatedResources []*apigatewayfern.ResourceReference
	var lambdaFunctions []*apigatewayfern.ResourceReference
	var cloudwatchLogs []*apigatewayfern.ResourceReference
	var iamRoles []*apigatewayfern.ResourceReference
	var errors []string

	// Track discovered resources to avoid duplicates
	discovered := make(map[string]bool)

	// Discover resources from route integrations
	for _, route := range routes {
		if route.Integration != nil {
			if route.Integration.AwsProxy != nil {
				arn := route.Integration.AwsProxy.Arn
				if !discovered[arn] && arn != "" {
					resourceType := identifyResourceType(arn, "")
					resource := &apigatewayfern.ResourceReference{
						Arn:        &arn,
						Type:       resourceType,
						Region:     &region,
						Name:       extractResourceNameFromArn(arn),
						ResourceId: extractResourceIDFromArn(arn),
					}

					// Categorize by type
					switch resourceType {
					case apigatewayfern.ResourceTypeLambdaFunction:
						lambdaFunctions = append(lambdaFunctions, resource)
					case apigatewayfern.ResourceTypeIamRole:
						iamRoles = append(iamRoles, resource)
					default:
						relatedResources = append(relatedResources, resource)
					}
					discovered[arn] = true
				}
			}
			if route.Integration.Aws != nil {
				arn := route.Integration.Aws.Arn
				if !discovered[arn] && arn != "" {
					resourceType := identifyResourceType(arn, "")
					resource := &apigatewayfern.ResourceReference{
						Arn:        &arn,
						Type:       resourceType,
						Region:     &region,
						Name:       extractResourceNameFromArn(arn),
						ResourceId: extractResourceIDFromArn(arn),
					}

					// Categorize by type
					switch resourceType {
					case apigatewayfern.ResourceTypeLambdaFunction:
						lambdaFunctions = append(lambdaFunctions, resource)
					case apigatewayfern.ResourceTypeIamRole:
						iamRoles = append(iamRoles, resource)
					default:
						relatedResources = append(relatedResources, resource)
					}
					discovered[arn] = true
				}
			}
			// Discover HTTP endpoints and other URI-based integrations
			if route.Integration.Http != nil || route.Integration.HttpProxy != nil {
				var uri string
				if route.Integration.Http != nil {
					uri = route.Integration.Http.Uri
				} else if route.Integration.HttpProxy != nil {
					uri = route.Integration.HttpProxy.Uri
				}

				if !discovered[uri] && uri != "" {
					resourceType := identifyResourceType("", uri)
					resourceName := extractResourceNameFromURI(uri)
					resourceID := extractResourceIDFromURI(uri)

					resource := &apigatewayfern.ResourceReference{
						Uri:        &uri, // For HTTP endpoints, use URI
						Type:       resourceType,
						Region:     &region,
						Name:       resourceName,
						ResourceId: resourceID,
					}

					// Categorize by type
					switch resourceType {
					case apigatewayfern.ResourceTypeEc2Instance:
						relatedResources = append(relatedResources, resource)
					case apigatewayfern.ResourceTypeApplicationLoadBalancer,
						apigatewayfern.ResourceTypeNetworkLoadBalancer,
						apigatewayfern.ResourceTypeLoadBalancer:
						relatedResources = append(relatedResources, resource)
					default:
						relatedResources = append(relatedResources, resource)
					}
					discovered[uri] = true
				}
			}
		}

		// Discover IAM roles from authorizers
		if route.Authorizer != nil && route.Authorizer.Credentials != nil {
			arn := *route.Authorizer.Credentials
			if !discovered[arn] && isIAMRole(arn) {
				iamRoles = append(iamRoles, &apigatewayfern.ResourceReference{
					Arn:        &arn,
					Type:       apigatewayfern.ResourceTypeIamRole,
					Region:     &region,
					Name:       extractResourceNameFromArn(arn),
					ResourceId: extractResourceIDFromArn(arn),
				})
				discovered[arn] = true
			}
		}
	}

	// Discover CloudWatch Log Groups from access log settings
	stages, err := client.GetStages(ctx, &apigatewayv2.GetStagesInput{ApiId: &apiID})
	if err == nil {
		for _, stage := range stages.Items {
			if stage.AccessLogSettings != nil && stage.AccessLogSettings.DestinationArn != nil {
				arn := *stage.AccessLogSettings.DestinationArn
				if !discovered[arn] && isCloudWatchLogGroup(arn) {
					cloudwatchLogs = append(cloudwatchLogs, &apigatewayfern.ResourceReference{
						Arn:        &arn,
						Type:       apigatewayfern.ResourceTypeCloudwatchLogGroup,
						Region:     &region,
						Name:       extractResourceNameFromArn(arn),
						ResourceId: extractResourceIDFromArn(arn),
					})
					discovered[arn] = true
				}
			}
		}
	}

	// Add all discovered resources to relatedResources for consolidated view
	relatedResources = append(relatedResources, lambdaFunctions...)
	relatedResources = append(relatedResources, cloudwatchLogs...)
	relatedResources = append(relatedResources, iamRoles...)

	return relatedResources, lambdaFunctions, cloudwatchLogs, iamRoles, errors
}
