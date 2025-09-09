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

	// Discover resource relationships
	relatedResources, lambdaFunctions, cloudwatchLogs, iamRoles, errs := discoverV1ResourceRelationships(ctx, client, *api.Id, routes, region)
	errors = append(errors, errs...)

	// Perform security analysis
	securityAnalysis := analyzeAPISecurity(routes, certificates, accessLogSettings, nil, apiKeys)

	var apiKeySource *string
	if api.ApiKeySource != "" {
		keySource := string(api.ApiKeySource)
		apiKeySource = &keySource
	}

	var stageName string
	if stage.StageName != nil {
		stageName = *stage.StageName
	}

	restAPIGateway := &apigatewayfern.RestApiGateway{
		Version:                apigatewayfern.ApiGatewayVersionV1,
		Region:                 region,
		Id:                     *api.Id,
		Name:                   api.Name,
		CreatedTime:            api.CreatedDate,
		Description:            api.Description,
		EndpointConfiguration:  endpointType,
		Certificates:           certificates,
		AccessLogSettings:      accessLogSettings,
		RelatedResources:       relatedResources,
		LambdaFunctions:        lambdaFunctions,
		CloudwatchLogs:         cloudwatchLogs,
		IamRoles:               iamRoles,
		SecurityAnalysis:       securityAnalysis,
		BaseUrl:                baseURL,
		Stage:                  stageName,
		Paths:                  routes,
		ApiKeySource:           apiKeySource,
		ApiKeys:                apiKeys,
		UsagePlans:             usagePlans,
		ClientCertificateId:    stage.ClientCertificateId,
		MinimumCompressionSize: convertInt32PtrToIntPtr(api.MinimumCompressionSize),
	}

	return apigatewayfern.NewApiGatewayFromRest(restAPIGateway), errors
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

// convertV1Integration converts AWS API Gateway integration to Fern Integration with resource discovery
func convertV1Integration(methodIntegration *types.Integration) (*apigatewayfern.Integration, error) {
	switch methodIntegration.Type {
	case types.IntegrationTypeHttp:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP integration missing URI")
		}
		resourceRef := discoverResourceFromURI(*methodIntegration.Uri)
		return apigatewayfern.NewIntegrationFromHttp(&apigatewayfern.HttpIntegration{
			Uri:               *methodIntegration.Uri,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeAws:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS integration missing ARN")
		}
		resourceRef := discoverResourceFromArn(*methodIntegration.Uri)
		return apigatewayfern.NewIntegrationFromAws(&apigatewayfern.AwsIntegration{
			Arn:               *methodIntegration.Uri,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeHttpProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("HTTP Proxy integration missing URI")
		}
		resourceRef := discoverResourceFromURI(*methodIntegration.Uri)
		return apigatewayfern.NewIntegrationFromHttpProxy(&apigatewayfern.HttpProxyIntegration{
			Uri:               *methodIntegration.Uri,
			ResourceReference: resourceRef,
		}), nil

	case types.IntegrationTypeAwsProxy:
		if methodIntegration.Uri == nil {
			return nil, fmt.Errorf("AWS Proxy integration missing ARN")
		}
		resourceRef := discoverResourceFromArn(*methodIntegration.Uri)
		return apigatewayfern.NewIntegrationFromAwsProxy(&apigatewayfern.AwsProxyIntegration{
			Arn:               *methodIntegration.Uri,
			ResourceReference: resourceRef,
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
func getAccessLogSettings(stage types.Stage) (*apigatewayfern.AccessLogSettings, error) {
	if stage.AccessLogSettings == nil || stage.AccessLogSettings.DestinationArn == nil {
		return nil, nil
	}

	return &apigatewayfern.AccessLogSettings{
		DestinationArn: *stage.AccessLogSettings.DestinationArn,
		Format:         stage.AccessLogSettings.Format,
	}, nil
}

// discoverV1ResourceRelationships discovers related AWS resources for a REST API
func discoverV1ResourceRelationships(ctx context.Context, client *apigateway.Client, apiID string, routes []*apigatewayfern.Route, region string) ([]*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []*apigatewayfern.ResourceReference, []string) {
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
	stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: &apiID})
	if err == nil {
		for _, stage := range stages.Item {
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

// discoverResourceFromArn extracts detailed resource information from an ARN
func discoverResourceFromArn(arn string) *apigatewayfern.ResourceReference {
	if arn == "" {
		return nil
	}

	resourceType := identifyResourceType(arn, "")
	resourceName := extractResourceNameFromArn(arn)
	resourceID := extractResourceIDFromArn(arn)

	return &apigatewayfern.ResourceReference{
		Type:       resourceType,
		Arn:        &arn,
		ResourceId: resourceID,
		Name:       resourceName,
	}
}

// discoverResourceFromURI extracts detailed resource information from a URI
func discoverResourceFromURI(uri string) *apigatewayfern.ResourceReference {
	if uri == "" {
		return nil
	}

	resourceType := identifyResourceType("", uri)
	resourceName := extractResourceNameFromURI(uri)
	resourceID := extractResourceIDFromURI(uri)

	return &apigatewayfern.ResourceReference{
		Type:       resourceType,
		Uri:        &uri,
		ResourceId: resourceID,
		Name:       resourceName,
	}
}

// extractResourceIDFromArn extracts resource ID from ARN
func extractResourceIDFromArn(arn string) *string {
	if arn == "" {
		return nil
	}

	// For Lambda functions: arn:aws:lambda:region:account:function:function-name or function:function-name:version/alias
	if strings.Contains(arn, ":lambda:") {
		parts := strings.Split(arn, ":")
		if len(parts) >= 7 {
			functionName := parts[6]
			// Remove version/alias if present (function-name:version or function-name:$LATEST)
			if strings.Contains(functionName, ":") {
				functionName = strings.Split(functionName, ":")[0]
			}
			return &functionName
		}
	}

	// For IAM roles: arn:aws:iam::account:role/role-name
	if strings.Contains(arn, ":iam:") && strings.Contains(arn, ":role/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			roleName := parts[len(parts)-1]
			return &roleName
		}
	}

	// For Load Balancers: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id or targetgroup/name/id
	if strings.Contains(arn, ":elasticloadbalancing:") {
		parts := strings.Split(arn, "/")
		if len(parts) >= 3 {
			// For load balancers, use the name (index 2)
			if len(parts) >= 4 && (strings.Contains(arn, "/app/") || strings.Contains(arn, "/net/") || strings.Contains(arn, "/gwy/")) {
				lbName := parts[2]
				return &lbName
			}
			// For target groups
			if strings.Contains(arn, "/targetgroup/") {
				tgName := parts[2]
				return &tgName
			}
		}
	}

	// For SNS topics: arn:aws:sns:region:account:topic-name
	if strings.Contains(arn, ":sns:") {
		parts := strings.Split(arn, ":")
		if len(parts) >= 6 {
			topicName := parts[5]
			return &topicName
		}
	}

	// For SQS queues: arn:aws:sqs:region:account:queue-name
	if strings.Contains(arn, ":sqs:") {
		parts := strings.Split(arn, ":")
		if len(parts) >= 6 {
			queueName := parts[5]
			return &queueName
		}
	}

	// For Kinesis streams: arn:aws:kinesis:region:account:stream/stream-name
	// For Kinesis delivery streams: arn:aws:firehose:region:account:deliverystream/stream-name
	if strings.Contains(arn, ":kinesis:") || strings.Contains(arn, ":firehose:") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			streamName := parts[len(parts)-1]
			return &streamName
		}
	}

	// For S3 buckets: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/key
	if strings.Contains(arn, ":s3:::") {
		parts := strings.Split(arn, ":::")
		if len(parts) > 1 {
			bucketPath := parts[1]
			// Extract bucket name (before any slash)
			bucketName := strings.Split(bucketPath, "/")[0]
			return &bucketName
		}
	}

	// For ECS services: arn:aws:ecs:region:account:service/cluster-name/service-name
	if strings.Contains(arn, ":ecs:") && strings.Contains(arn, ":service/") {
		parts := strings.Split(arn, "/")
		if len(parts) >= 3 {
			serviceName := parts[len(parts)-1]
			return &serviceName
		}
	}

	// For DynamoDB tables: arn:aws:dynamodb:region:account:table/table-name
	if strings.Contains(arn, ":dynamodb:") && strings.Contains(arn, ":table/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			tableName := parts[len(parts)-1]
			return &tableName
		}
	}

	// For CloudWatch Log Groups: arn:aws:logs:region:account:log-group:/aws/lambda/function-name
	if strings.Contains(arn, ":logs:") && strings.Contains(arn, ":log-group:") {
		parts := strings.Split(arn, ":log-group:")
		if len(parts) > 1 {
			logGroupName := parts[1]
			// Remove any additional parts after log group name
			if strings.Contains(logGroupName, ":") {
				logGroupName = strings.Split(logGroupName, ":")[0]
			}
			return &logGroupName
		}
	}

	// For EventBridge rules: arn:aws:events:region:account:rule/rule-name
	if strings.Contains(arn, ":events:") && strings.Contains(arn, ":rule/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			ruleName := parts[len(parts)-1]
			return &ruleName
		}
	}

	// For WAF Web ACLs: arn:aws:wafv2:region:account:global/webacl/name/id
	if strings.Contains(arn, ":wafv2:") && strings.Contains(arn, ":webacl/") {
		parts := strings.Split(arn, "/")
		if len(parts) >= 4 {
			webACLName := parts[2]
			return &webACLName
		}
	}

	// For Cognito User Pools: arn:aws:cognito-idp:region:account:userpool/pool-id
	if strings.Contains(arn, ":cognito-idp:") && strings.Contains(arn, ":userpool/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			poolID := parts[len(parts)-1]
			return &poolID
		}
	}

	// For VPC Links: arn:aws:apigatewayv2:region:account:vpclink/vpc-link-id
	if strings.Contains(arn, ":apigatewayv2:") && strings.Contains(arn, ":vpclink/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 1 {
			vpcLinkID := parts[len(parts)-1]
			return &vpcLinkID
		}
	}

	// Default: try to extract from the end of the ARN using either / or : separator
	if strings.Contains(arn, "/") {
		parts := strings.Split(arn, "/")
		if len(parts) > 0 {
			lastPart := parts[len(parts)-1]
			if lastPart != "" {
				return &lastPart
			}
		}
	}

	parts := strings.Split(arn, ":")
	if len(parts) > 0 {
		lastPart := parts[len(parts)-1]
		if lastPart != "" && lastPart != ":" {
			return &lastPart
		}
	}

	return nil
}

// extractResourceIDFromURI extracts resource ID from URI (for EC2, load balancers, etc.)
func extractResourceIDFromURI(uri string) *string {
	if uri == "" {
		return nil
	}

	// Clean the URI first
	cleanedURI := strings.TrimSpace(uri)

	// For EC2 public DNS: ec2-xx-xx-xx-xx.region.compute.amazonaws.com
	if strings.Contains(cleanedURI, ".compute.amazonaws.com") {
		if strings.Contains(cleanedURI, "ec2-") {
			// Extract the ec2-xx-xx-xx-xx part as the instance identifier
			parts := strings.Split(cleanedURI, ".")
			for _, part := range parts {
				// Remove protocol prefix if present
				part = strings.TrimPrefix(part, "https://")
				part = strings.TrimPrefix(part, "http://")
				if strings.HasPrefix(part, "ec2-") {
					return &part
				}
			}
		}
		// For internal EC2 names or other compute endpoints, extract hostname
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			return &host
		}
	}

	// For load balancers: internal-name-xxx.region.elb.amazonaws.com
	if strings.Contains(cleanedURI, ".elb.amazonaws.com") || strings.Contains(cleanedURI, ".elb.") {
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			// Extract load balancer name (everything before the first dot)
			lbName := strings.Split(host, ".")[0]
			if lbName != "" {
				return &lbName
			}
		}
	}

	// For CloudFront distributions: dxxxxxxxxxxxxx.cloudfront.net
	if strings.Contains(cleanedURI, ".cloudfront.net") {
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			distributionID := strings.Split(host, ".")[0]
			if distributionID != "" {
				return &distributionID
			}
		}
	}

	// For API Gateway custom domains: api.example.com
	if strings.Contains(cleanedURI, ".execute-api.") && strings.Contains(cleanedURI, ".amazonaws.com") {
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			// Extract API Gateway ID (first part before .execute-api)
			apiGwID := strings.Split(host, ".execute-api.")[0]
			if apiGwID != "" {
				return &apiGwID
			}
		}
	}

	// For private IP addresses, use the IP as the identifier
	if strings.Contains(cleanedURI, "://10.") || strings.Contains(cleanedURI, "://172.") || strings.Contains(cleanedURI, "://192.168.") ||
		strings.HasPrefix(cleanedURI, "10.") || strings.HasPrefix(cleanedURI, "172.") || strings.HasPrefix(cleanedURI, "192.168.") {
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			return &host
		}
	}

	// For localhost and other local addresses
	if strings.Contains(cleanedURI, "localhost") || strings.Contains(cleanedURI, "127.0.0.1") {
		host := extractHostFromURI(cleanedURI)
		if host != "" {
			return &host
		}
	}

	// For other URIs, extract hostname
	host := extractHostFromURI(cleanedURI)
	if host != "" {
		return &host
	}

	// If no protocol, assume it's already a hostname/identifier
	if !strings.Contains(cleanedURI, "://") && cleanedURI != "" {
		return &cleanedURI
	}

	return nil
}

// extractHostFromURI helper function to extract hostname from URI
func extractHostFromURI(uri string) string {
	if uri == "" {
		return ""
	}

	// Handle URI with protocol
	if strings.Contains(uri, "://") {
		parts := strings.Split(uri, "://")
		if len(parts) > 1 {
			// Get everything after protocol
			hostPart := parts[1]
			// Remove path (everything after first /)
			hostPart = strings.Split(hostPart, "/")[0]
			// Remove port (everything after first :)
			hostPart = strings.Split(hostPart, ":")[0]
			// Remove query parameters (everything after ?)
			hostPart = strings.Split(hostPart, "?")[0]
			return hostPart
		}
	}

	// Handle URI without protocol (assume it's hostname:port or just hostname)
	// Remove port if present
	hostPart := strings.Split(uri, ":")[0]
	// Remove path if present
	hostPart = strings.Split(hostPart, "/")[0]
	// Remove query parameters
	hostPart = strings.Split(hostPart, "?")[0]

	return hostPart
}
