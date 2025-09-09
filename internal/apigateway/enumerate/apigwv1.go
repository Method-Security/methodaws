package apigateway

import (
	"context"
	"fmt"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// enumerateV1ApiGatewaysAllRegions enumerates v1 API Gateways (REST APIs) across all specified regions
func enumerateV1ApiGatewaysAllRegions(ctx context.Context, awsConfig aws.Config, regions []string) ([]*apigatewayfern.ApiGateway, []string) {
	log := svc1log.FromContext(ctx)
	var allAPIGateways []*apigatewayfern.ApiGateway
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
func enumerateV1ApiGatewaysForRegion(ctx context.Context, cfg aws.Config, region string) ([]*apigatewayfern.ApiGateway, []string) {
	log := svc1log.FromContext(ctx)
	regionCfg := cfg.Copy()
	regionCfg.Region = region

	client := apigateway.NewFromConfig(regionCfg)
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	var apiGateways []*apigatewayfern.ApiGateway
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

		for _, api := range result.Items {
			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				errors = append(errors, err.Error())
				continue
			}

			// Process each stage as a separate API Gateway instance
			for _, stage := range stages.Item {
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

// convertV1RestAPIToFern converts AWS REST API to Fern ApiGateway struct
func convertV1RestAPIToFern(ctx context.Context, client *apigateway.Client, api types.RestApi, stage types.Stage, region string) (*apigatewayfern.ApiGateway, []string) {
	var errors []string

	// Construct base URL for this stage
	baseURL := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", *api.Id, region, *stage.StageName)

	// Get resources and methods with security info
	routes, errs := getRestAPIRoutes(ctx, client, *api.Id)
	errors = append(errors, errs...)

	// Get endpoint configuration
	endpointType, err := getEndpointConfiguration(api.EndpointConfiguration)
	if err != nil {
		errors = append(errors, err.Error())
	}

	// Get certificates
	certificates, errs := getAPICertificates(ctx, client)
	errors = append(errors, errs...)

	// Get API keys and usage plans
	apiKeys, usagePlans, errs := getAPIKeysAndUsagePlans(ctx, client, *api.Id)
	errors = append(errors, errs...)

	// Get access log settings from stage
	accessLogSettings, err := getAccessLogSettings(stage)
	if err != nil {
		errors = append(errors, err.Error())
	}

	apiKeySource := string(api.ApiKeySource)
	apiGateway := &apigatewayfern.ApiGateway{
		Id:          api.Id,
		Version:     apigatewayfern.ApiGatewayVersionV1,
		Name:        api.Name,
		Region:      region,
		CreatedTime: api.CreatedDate,
		Description: api.Description,
		// Security properties
		EndpointConfiguration: endpointType,
		Certificates:          certificates,
		AccessLogSettings:     accessLogSettings,
		// V1 specific properties
		BaseUrl:                &baseURL,
		Stage:                  stage.StageName,
		Paths:                  routes,
		ApiKeySource:           &apiKeySource,
		ApiKeys:                apiKeys,
		UsagePlans:             usagePlans,
		ClientCertificateId:    stage.ClientCertificateId,
		MinimumCompressionSize: convertInt32PtrToIntPtr(api.MinimumCompressionSize),
	}

	return apiGateway, errors
}

// getRestAPIRoutes retrieves routes/paths for a REST API
func getRestAPIRoutes(ctx context.Context, client *apigateway.Client, apiID string) ([]*apigatewayfern.Route, []string) {
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
				integ, err := convertV1Integration(method.MethodIntegration)
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

			// Get authorizer info if present
			var authorizer *apigatewayfern.Authorizer
			if method.AuthorizerId != nil {
				authResult, err := client.GetAuthorizer(ctx, &apigateway.GetAuthorizerInput{
					RestApiId:    &apiID,
					AuthorizerId: method.AuthorizerId,
				})
				if err == nil {
					authorizer = &apigatewayfern.Authorizer{
						Id:                           *authResult.Id,
						Name:                         *authResult.Name,
						Type:                         *authType, // Use the converted type
						Uri:                          authResult.AuthorizerUri,
						Credentials:                  authResult.AuthorizerCredentials,
						IdentitySource:               convertStringPtrToSlice(authResult.IdentitySource),
						IdentityValidationExpression: authResult.IdentityValidationExpression,
						ResultTtlInSeconds:           convertInt32PtrToIntPtr(authResult.AuthorizerResultTtlInSeconds),
					}
					if authResult.ProviderARNs != nil {
						authorizer.ProviderArns = authResult.ProviderARNs
					}
				}
			}

			route := &apigatewayfern.Route{
				Path:           *resource.Path,
				Method:         methodName,
				Integration:    integration,
				Authorization:  authType,
				Authorizer:     authorizer,
				ApiKeyRequired: method.ApiKeyRequired,
			}
			routes = append(routes, route)
		}
	}

	return routes, errors
}

// convertV1Integration converts AWS API Gateway integration to Fern Integration
func convertV1Integration(methodIntegration *types.Integration) (*apigatewayfern.Integration, error) {
	switch methodIntegration.Type {
	case types.IntegrationTypeHttp:
		return apigatewayfern.NewIntegrationFromHttp(&apigatewayfern.HttpIntegration{
			Uri: *methodIntegration.Uri,
		}), nil

	case types.IntegrationTypeAws:
		return apigatewayfern.NewIntegrationFromAws(&apigatewayfern.AwsIntegration{
			Arn: *methodIntegration.Uri,
		}), nil

	case types.IntegrationTypeHttpProxy:
		return apigatewayfern.NewIntegrationFromHttpProxy(&apigatewayfern.HttpProxyIntegration{
			Uri: *methodIntegration.Uri,
		}), nil

	case types.IntegrationTypeAwsProxy:
		return apigatewayfern.NewIntegrationFromAwsProxy(&apigatewayfern.AwsProxyIntegration{
			Arn: *methodIntegration.Uri,
		}), nil

	case types.IntegrationTypeMock:
		return apigatewayfern.NewIntegrationFromMock(&apigatewayfern.MockIntegration{}), nil

	default:
		return nil, fmt.Errorf("unsupported integration type: %s", methodIntegration.Type)
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
				Arn:       *domain.CertificateArn,
				Name:      *domain.DomainName,
				IsDefault: false, // API Gateway doesn't have a "default" concept like this
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

// getAPIKeysAndUsagePlans retrieves API keys and usage plans
func getAPIKeysAndUsagePlans(ctx context.Context, client *apigateway.Client, apiID string) ([]string, []string, []string) {
	var apiKeys []string
	var usagePlans []string
	var errors []string

	// Get API keys
	keysResult, err := client.GetApiKeys(ctx, &apigateway.GetApiKeysInput{})
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for _, key := range keysResult.Items {
			if key.Id != nil {
				apiKeys = append(apiKeys, *key.Id)
			}
		}
	}

	// Get usage plans
	plansResult, err := client.GetUsagePlans(ctx, &apigateway.GetUsagePlansInput{})
	if err != nil {
		errors = append(errors, err.Error())
	} else {
		for _, plan := range plansResult.Items {
			if plan.Id != nil {
				usagePlans = append(usagePlans, *plan.Id)
			}
		}
	}

	return apiKeys, usagePlans, errors
}

// getAccessLogSettings converts stage access log settings
func getAccessLogSettings(stage types.Stage) (*apigatewayfern.AccessLogSettings, error) {
	if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
		return nil, nil
	}

	return &apigatewayfern.AccessLogSettings{
		DestinationArn: *stage.AccessLogSettings.DestinationArn,
		Format:         stage.AccessLogSettings.Format,
	}, nil
}
