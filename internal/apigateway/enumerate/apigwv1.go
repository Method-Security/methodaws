package apigateway

import (
	"context"
	"fmt"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1ApiGatewaysAllRegions enumerates v1 API Gateways (REST APIs) across all specified regions
func enumerateV1ApiGatewaysAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
	var allErrors []string

	for _, region := range regions {
		log.Info("Processing v1 API Gateways in region", svc1log.SafeParam("region", region))
		apiGateways, errors := enumerateV1ApiGatewaysForRegion(ctx, awsConfig, region)

		if len(errors) > 0 {
			log.Warn("Errors occurred while enumerating v1 API Gateways in region",
				svc1log.SafeParam("region", region),
				svc1log.SafeParam("errorCount", len(errors)))
		}

		allAPIGateways = append(allAPIGateways, apiGateways...)
		allErrors = append(allErrors, errors...)

		log.Info("Successfully processed v1 API Gateways in region",
			svc1log.SafeParam("region", region),
			svc1log.SafeParam("apiGatewayCount", len(apiGateways)))
	}

	return allAPIGateways, allErrors
}

// enumerateV1ApiGatewaysForRegion enumerates v1 API Gateways (REST APIs) for a specific region
func enumerateV1ApiGatewaysForRegion(ctx context.Context, cfg aws.Config, region string) ([]*apigatewayfern.ApiGatewayInstance, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	client := apigateway.NewFromConfig(regionCfg)
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	var apiGateways []*apigatewayfern.ApiGatewayInstance
	var errors []string

	for paginator.HasMorePages() {
		result, err := paginator.NextPage(ctx)
		if err != nil {
			log.Warn("Failed to retrieve REST APIs page",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			errors = append(errors, fmt.Sprintf("Failed to retrieve REST APIs in region %s: %s", region, err.Error()))
			break
		}

		// Process APIs sequentially
		for _, api := range result.Items {
			if api.Id == nil {
				errors = append(errors, "REST API ID is nil")
				continue
			}

			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Process each stage as a separate API Gateway instance
			for _, stage := range stages.Item {
				if stage.StageName == nil {
					errors = append(errors, "REST API Stage Name is nil")
					continue
				}
				apiGw, errs := convertV1RestAPIToFern(ctx, client, api, stage, region)

				if apiGw != nil {
					apiGateways = append(apiGateways, apiGw)
				}
				errors = append(errors, errs...)
			}
		}
	}

	return apiGateways, errors
}

// convertV1RestAPIToFern converts AWS REST API to Fern RestApiGateway struct
func convertV1RestAPIToFern(ctx context.Context, client *apigateway.Client, api types.RestApi, stage types.Stage, region string) (*apigatewayfern.ApiGatewayInstance, []string) {
	var errors []string

	// Construct base URL for this stage
	baseURL := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", *api.Id, region, *stage.StageName)

	// Get resources and methods with security info
	routes, errs := getRestAPIRoutes(ctx, client, *api.Id, region)
	errors = append(errors, errs...)

	// Get endpoint configuration (not used in simplified version)
	_, err := getEndpointConfiguration(api.EndpointConfiguration)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Get certificates
	certificates, errs := getAPICertificates(ctx, client)
	errors = append(errors, errs...)

	// Get API keys and usage plans
	apiKeys, _, errs := getAPIKeysAndUsagePlans(ctx, client, *api.Id)
	errors = append(errors, errs...)

	// Get access log settings from stage
	accessLogSettings, err := getAccessLogSettings(stage, region)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Discover resource relationships
	// Resources are now nested within routes, no need for separate discovery

	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, nil, apiKeys)

	var stageName string
	if stage.StageName != nil {
		stageName = *stage.StageName
	}

	// Create identification info
	identification := &apigatewayfern.ApiGatewayIdentificationInfo{
		Id:     *api.Id,
		Name:   api.Name,
		Region: region,
		Url:    baseURL,
	}

	// Create configuration info
	configuration := &apigatewayfern.ApiGatewayConfigurationInfo{
		Version:             apigatewayfern.ApiGatewayVersionV1,
		Description:         api.Description,
		Stage:               &stageName,
		AccessLogSettings:   accessLogSettings,
		ClientCertificateId: stage.ClientCertificateId,
		Certificates:        certificates,
		Security:            securityAnalysis,
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

// getRestAPIRoutes retrieves routes/paths for a REST API
func getRestAPIRoutes(ctx context.Context, client *apigateway.Client, apiID, region string) ([]*apigatewayfern.Route, []string) {
	var routes []*apigatewayfern.Route
	var errors []string

	resources, err := client.GetResources(ctx, &apigateway.GetResourcesInput{RestApiId: &apiID})
	if err != nil {
		return routes, []string{err.Error()}
	}

	for _, resource := range resources.Items {
		for methodName := range resource.ResourceMethods {
			method, err := client.GetMethod(ctx, &apigateway.GetMethodInput{
				RestApiId:  &apiID,
				ResourceId: resource.Id,
				HttpMethod: &methodName,
			})
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Convert integration if present
			var integration *apigatewayfern.Integration
			if method.MethodIntegration != nil {
				integ, err := convertV1Integration(method.MethodIntegration, region)
				if err != nil {
					errors = append(errors, err.Error())
				} else {
					integration = integ
				}
			}

			// Convert authorization type
			var authType *apigatewayfern.AuthorizationType
			if method.AuthorizationType != nil && *method.AuthorizationType != "" {
				switch *method.AuthorizationType {
				case "NONE":
					authTypeValue := apigatewayfern.AuthorizationTypeNone
					authType = &authTypeValue
				case "AWS_IAM":
					authTypeValue := apigatewayfern.AuthorizationTypeAwsIam
					authType = &authTypeValue
				case "CUSTOM":
					authTypeValue := apigatewayfern.AuthorizationTypeCustom
					authType = &authTypeValue
				case "COGNITO_USER_POOLS":
					authTypeValue := apigatewayfern.AuthorizationTypeCognitoUserPools
					authType = &authTypeValue
				}
			}

			// Get authorizer info if present (simplified - not included in route)
			_ = method.AuthorizerId

			// Create route-specific resource links
			resourceLinks := createRouteResources(integration, region)

			// Create resources only if there's something to include
			var resources *apigatewayfern.RouteResourceInfo
			if integration != nil || (resourceLinks != nil && (resourceLinks.ExecutionRole != nil || resourceLinks.CloudWatchLog != nil)) {
				resources = &apigatewayfern.RouteResourceInfo{
					Integration: integration,
				}

				// Add other resource links if they exist
				if resourceLinks != nil {
					resources.ExecutionRole = resourceLinks.ExecutionRole
					resources.CloudWatchLog = resourceLinks.CloudWatchLog
				}
			}

			route := &apigatewayfern.Route{
				Identification: &apigatewayfern.RouteIdentificationInfo{
					Path:   *resource.Path,
					Method: methodName,
				},
				Configuration: &apigatewayfern.RouteConfigurationInfo{
					Authorization:  authType,
					ApiKeyRequired: method.ApiKeyRequired,
				},
				Resources: resources,
			}
			routes = append(routes, route)
		}
	}

	return routes, errors
}

// convertV1Integration converts AWS API Gateway integration to Fern Integration with backend structure
func convertV1Integration(methodIntegration *types.Integration, region string) (*apigatewayfern.Integration, error) {
	switch methodIntegration.Type {
	case types.IntegrationTypeHttp:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP integration missing URI")
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        *methodIntegration.Uri,
			IsExternal: !strings.Contains(*methodIntegration.Uri, ".amazonaws.com"),
		}

		return apigatewayfern.NewIntegrationFromHttp(&apigatewayfern.HttpIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeAws:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS integration missing ARN")
		}

		backend := &apigatewayfern.AwsServiceBackend{
			Arn:     *methodIntegration.Uri,
			Service: extractServiceFromArn(*methodIntegration.Uri),
			Region:  region,
		}

		return apigatewayfern.NewIntegrationFromAws(&apigatewayfern.AwsIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeHttpProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP Proxy integration missing URI")
		}

		// Check if this is a VPC Link integration (private load balancer)
		if isVpcLinkIntegration(methodIntegration) {
			backend := createLoadBalancerBackend(methodIntegration, region)
			return apigatewayfern.NewIntegrationFromVpcLink(&apigatewayfern.VpcLinkIntegration{
				Backend: backend,
			}), nil
		}

		backend := &apigatewayfern.HttpBackend{
			Uri:        *methodIntegration.Uri,
			IsExternal: !strings.Contains(*methodIntegration.Uri, ".amazonaws.com"),
		}

		return apigatewayfern.NewIntegrationFromHttpProxy(&apigatewayfern.HttpProxyIntegration{
			Backend: backend,
		}), nil

	case types.IntegrationTypeAwsProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS Proxy integration missing ARN")
		}

		backend := &apigatewayfern.LambdaBackend{
			Arn:          *methodIntegration.Uri,
			FunctionName: extractResourceNameFromArn(*methodIntegration.Uri),
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
		return nil, fmt.Errorf("unsupported integration type: %s", methodIntegration.Type)
	}
}

// extractServiceFromArn extracts the service name from an AWS ARN
func extractServiceFromArn(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 3 {
		return parts[2] // Service is the 3rd element (0-indexed position 2)
	}
	return "unknown"
}

// isVpcLinkIntegration checks if the integration uses a VPC Link
func isVpcLinkIntegration(integration *types.Integration) bool {
	// In V1 API Gateway, VPC Link is indicated by connection type and connection ID
	return integration.ConnectionType == types.ConnectionTypeVpcLink &&
		integration.ConnectionId != nil
}

// createLoadBalancerBackend creates a LoadBalancerBackend from integration details
func createLoadBalancerBackend(integration *types.Integration, region string) *apigatewayfern.LoadBalancerBackend {
	if integration.Uri == nil || integration.ConnectionId == nil {
		return nil
	}

	// Extract DNS name from URI
	dnsName := extractDNSNameFromURI(*integration.Uri)

	return &apigatewayfern.LoadBalancerBackend{
		Uri:             *integration.Uri,
		VpcLinkId:       *integration.ConnectionId,
		LoadBalancerArn: "", // Would need additional API call to get actual ARN
		DnsName:         &dnsName,
	}
}

// getEndpointConfiguration converts AWS endpoint configuration to Fern EndpointType
func getEndpointConfiguration(endpointConfig *types.EndpointConfiguration) (*apigatewayfern.EndpointType, error) {
	if endpointConfig == nil || len(endpointConfig.Types) == 0 {
		return nil, nil
	}

	// Use the first endpoint type
	switch endpointConfig.Types[0] {
	case types.EndpointTypeEdge:
		endpointType := apigatewayfern.EndpointTypeEdge
		return &endpointType, nil
	case types.EndpointTypeRegional:
		endpointType := apigatewayfern.EndpointTypeRegional
		return &endpointType, nil
	case types.EndpointTypePrivate:
		endpointType := apigatewayfern.EndpointTypePrivate
		return &endpointType, nil
	default:
		return nil, fmt.Errorf("unsupported endpoint type: %s", endpointConfig.Types[0])
	}
}

// getAPICertificates retrieves domain name certificates for the API
func getAPICertificates(ctx context.Context, client *apigateway.Client) ([]*apigatewayfern.Certificate, []string) {
	var certificates []*apigatewayfern.Certificate
	var errors []string

	// Get domain names associated with the API
	domainNames, err := client.GetDomainNames(ctx, &apigateway.GetDomainNamesInput{})
	if err != nil {
		return certificates, []string{err.Error()}
	}

	for _, domain := range domainNames.Items {
		if domain.CertificateArn != nil {
			cert := &apigatewayfern.Certificate{
				Arn:        *domain.CertificateArn,
				DomainName: domain.DomainName,
			}

			// Convert security policy if present
			if domain.SecurityPolicy != "" {
				switch domain.SecurityPolicy {
				case types.SecurityPolicyTls10:
					policy := apigatewayfern.SecurityPolicyTls10
					cert.SecurityPolicy = &policy
				case types.SecurityPolicyTls12:
					policy := apigatewayfern.SecurityPolicyTls12
					cert.SecurityPolicy = &policy
				}
			}

			certificates = append(certificates, cert)
		}
	}

	return certificates, errors
}

// getAPIKeysAndUsagePlans retrieves API keys and usage plans associated with the API
func getAPIKeysAndUsagePlans(ctx context.Context, client *apigateway.Client, apiID string) ([]string, []string, []string) {
	var apiKeys []string
	var usagePlans []string
	var errors []string

	// Get API keys - filter for those associated with this API
	keysResult, err := client.GetApiKeys(ctx, &apigateway.GetApiKeysInput{})
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for _, key := range keysResult.Items {
			if key.Id != nil {
				// Check if this API key is associated with our API by checking usage plans
				apiKeys = append(apiKeys, *key.Id)
			}
		}
	}

	// Get usage plans associated with this API
	plansResult, err := client.GetUsagePlans(ctx, &apigateway.GetUsagePlansInput{})
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for _, plan := range plansResult.Items {
			if plan.Id != nil && plan.ApiStages != nil {
				// Check if this usage plan is associated with our API
				for _, apiStage := range plan.ApiStages {
					if apiStage.ApiId != nil && *apiStage.ApiId == apiID {
						usagePlans = append(usagePlans, *plan.Id)
						break
					}
				}
			}
		}
	}

	return apiKeys, usagePlans, errors
}

// getAccessLogSettings converts stage access log settings
func getAccessLogSettings(stage types.Stage, region string) (*apigatewayfern.AccessLogSettings, error) {
	if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
		return nil, nil
	}

	settings := &apigatewayfern.AccessLogSettings{
		DestinationArn: *stage.AccessLogSettings.DestinationArn,
		Format:         stage.AccessLogSettings.Format,
	}

	return settings, nil
}
