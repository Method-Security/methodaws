package apigateway

import (
	"context"
	"strings"

	apigatewayfern "github.com/Method-Security/methodaws/generated/go/apigateway"
	common "github.com/Method-Security/methodaws/generated/go/common"
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
		Result: &apigatewayfern.ApiGatewayEnumerateResult{},
		Config: &config,
	}

	var allAPIGateways []*apigatewayfern.ApiGatewayInstance
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

// Helper functions for resource identification
func isLambdaFunction(arn string) bool {
	return strings.Contains(arn, ":lambda:")
}

func isIAMRole(arn string) bool {
	return strings.Contains(arn, ":iam:") && strings.Contains(arn, ":role/")
}

func isCloudWatchLogGroup(arn string) bool {
	return strings.Contains(arn, ":logs:") && strings.Contains(arn, ":log-group:")
}

func isSNSTopic(arn string) bool {
	return strings.Contains(arn, ":sns:")
}

func isSQSQueue(arn string) bool {
	return strings.Contains(arn, ":sqs:")
}

func isKinesisStream(arn string) bool {
	return strings.Contains(arn, ":kinesis:") && (strings.Contains(arn, ":stream/") || strings.Contains(arn, ":delivery-stream/"))
}

func isDynamoDBTable(arn string) bool {
	return strings.Contains(arn, ":dynamodb:") && strings.Contains(arn, ":table/")
}

func isEventBridge(arn string) bool {
	return strings.Contains(arn, ":events:") && (strings.Contains(arn, ":event-bus/") || strings.Contains(arn, ":rule/"))
}

func isWAFWebACL(arn string) bool {
	return strings.Contains(arn, ":wafv2:") && strings.Contains(arn, ":webacl/")
}

func isCognitoUserPool(arn string) bool {
	return strings.Contains(arn, ":cognito-idp:") && strings.Contains(arn, ":userpool/")
}

func isVPCLink(arn string) bool {
	return strings.Contains(arn, ":apigatewayv2:") && strings.Contains(arn, ":vpclink/")
}

func isLoadBalancer(arn string) bool {
	return strings.Contains(arn, ":elasticloadbalancing:")
}

func isHTTPEndpoint(uri string) bool {
	return strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://")
}

func identifyResourceType(arn, uri string) apigatewayfern.ResourceType {
	if arn != "" {
		if isLambdaFunction(arn) {
			return apigatewayfern.ResourceTypeLambdaFunction
		}
		if isIAMRole(arn) {
			return apigatewayfern.ResourceTypeIamRole
		}
		if isCloudWatchLogGroup(arn) {
			return apigatewayfern.ResourceTypeCloudwatchLogGroup
		}
		if isSNSTopic(arn) {
			return apigatewayfern.ResourceTypeSnsTopic
		}
		if isSQSQueue(arn) {
			return apigatewayfern.ResourceTypeSqsQueue
		}
		if isKinesisStream(arn) {
			return apigatewayfern.ResourceTypeKinesisStream
		}
		if isLoadBalancer(arn) {
			if strings.Contains(arn, ":loadbalancer/app/") {
				return apigatewayfern.ResourceTypeApplicationLoadBalancer
			} else if strings.Contains(arn, ":loadbalancer/net/") {
				return apigatewayfern.ResourceTypeNetworkLoadBalancer
			}
			return apigatewayfern.ResourceTypeLoadBalancer
		}
		if strings.Contains(arn, ":s3:") {
			return apigatewayfern.ResourceTypeS3Bucket
		}
		if strings.Contains(arn, ":ecs:") && strings.Contains(arn, ":service/") {
			return apigatewayfern.ResourceTypeEcsService
		}
		if isDynamoDBTable(arn) {
			return apigatewayfern.ResourceTypeDynamodbTable
		}
		if isEventBridge(arn) {
			return apigatewayfern.ResourceTypeEventbridgeRule
		}
		if isWAFWebACL(arn) {
			return apigatewayfern.ResourceTypeWafWebAcl
		}
		if isCognitoUserPool(arn) {
			return apigatewayfern.ResourceTypeCognitoUserPool
		}
		if isVPCLink(arn) {
			return apigatewayfern.ResourceTypeVpcLink
		}
	}

	if uri != "" {
		if isHTTPEndpoint(uri) {
			// Try to identify if it's pointing to EC2 instances
			if isEC2Endpoint(uri) {
				return apigatewayfern.ResourceTypeEc2Instance
			}
			return apigatewayfern.ResourceTypeHttpEndpoint
		}
	}

	return apigatewayfern.ResourceTypeOther
}

// createLambdaReference creates a Lambda reference from an ARN
func createLambdaReference(arn, region string) *apigatewayfern.LambdaReference {
	if !isLambdaFunction(arn) {
		return nil
	}

	functionName := extractResourceNameFromArn(arn)
	if functionName == nil {
		return nil
	}

	return &apigatewayfern.LambdaReference{
		Arn:          arn,
		FunctionName: functionName,
		Region:       region,
	}
}

// createIamRoleReference creates an IAM role reference from an ARN
func createIamRoleReference(arn, region string) *common.IamRoleReference {
	if !isIAMRole(arn) {
		return nil
	}

	roleName := extractResourceNameFromArn(arn)
	if roleName == nil {
		return nil
	}

	return &common.IamRoleReference{
		Arn:      arn,
		RoleName: roleName,
		Region:   region,
	}
}

// createCloudWatchLogReference creates a CloudWatch log reference from an ARN
func createCloudWatchLogReference(arn, region string) *common.CloudWatchLogReference {
	if !isCloudWatchLogGroup(arn) {
		return nil
	}

	logGroupName := extractResourceNameFromArn(arn)
	if logGroupName == nil {
		return nil
	}

	return &common.CloudWatchLogReference{
		Arn:          arn,
		LogGroupName: *logGroupName,
		Region:       region,
	}
}

// createLoadBalancerReference creates a load balancer reference from an ARN or URI
func createLoadBalancerReference(arn, uri, region string) *common.LoadBalancerReference {
	if arn != "" && isLoadBalancer(arn) {
		dnsName := ""
		// Extract DNS name if available in URI
		if uri != "" {
			if name := extractResourceNameFromURI(uri); name != nil {
				dnsName = *name
			}
		}

		lbType := "ALB"
		if strings.Contains(arn, ":loadbalancer/net/") {
			lbType = "NLB"
		}

		return &common.LoadBalancerReference{
			Arn:     arn,
			DnsName: &dnsName,
			Region:  region,
			Type:    common.LoadBalancerType(lbType),
		}
	}

	return nil
}

// isEC2Endpoint checks if URI appears to point to EC2 instances
func isEC2Endpoint(uri string) bool {
	// Common patterns for EC2 endpoints
	if strings.Contains(uri, ".compute.amazonaws.com") ||
		strings.Contains(uri, ".compute-1.amazonaws.com") ||
		strings.Contains(uri, "ec2-") {
		return true
	}

	// Private IP ranges that might indicate EC2
	if strings.Contains(uri, "://10.") ||
		strings.Contains(uri, "://172.") ||
		strings.Contains(uri, "://192.168.") {
		return true
	}

	return false
}

func extractResourceNameFromArn(arn string) *string {
	if arn == "" {
		return nil
	}

	parts := strings.Split(arn, "/")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name != "" {
			return &name
		}
	}

	// Fallback: extract from colon-separated parts
	parts = strings.Split(arn, ":")
	if len(parts) > 0 {
		name := parts[len(parts)-1]
		if name != "" {
			return &name
		}
	}

	return nil
}

// extractResourceNameFromURI extracts a meaningful name from a URI
func extractResourceNameFromURI(uri string) *string {
	if uri == "" {
		return nil
	}

	// For EC2 public DNS names
	if strings.Contains(uri, ".compute.amazonaws.com") {
		// Extract instance ID or public DNS
		if strings.Contains(uri, "ec2-") {
			parts := strings.Split(uri, ".")
			for _, part := range parts {
				if strings.HasPrefix(part, "ec2-") {
					return &part
				}
			}
		}
	}

	// For load balancers
	if strings.Contains(uri, ".elb.amazonaws.com") || strings.Contains(uri, ".elb.") {
		parts := strings.Split(uri, ".")
		if len(parts) > 0 && parts[0] != "" {
			// Remove protocol if present
			name := strings.TrimPrefix(parts[0], "https://")
			name = strings.TrimPrefix(name, "http://")
			return &name
		}
	}

	// For private IPs, use the whole URI as name
	if strings.Contains(uri, "://10.") || strings.Contains(uri, "://172.") || strings.Contains(uri, "://192.168.") {
		return &uri
	}

	// Default: extract host from URI
	if strings.Contains(uri, "://") {
		parts := strings.Split(uri, "://")
		if len(parts) > 1 {
			host := strings.Split(parts[1], "/")[0]
			host = strings.Split(host, ":")[0] // Remove port if present
			if host != "" {
				return &host
			}
		}
	}

	return &uri
}

// analyzeAPISecurity performs security analysis on API Gateway configurations
func analyzeAPISecurity(routes []*apigatewayfern.Route, certificates []*apigatewayfern.Certificate, accessLogSettings *apigatewayfern.AccessLogSettings, corsConfig *apigatewayfern.CorsConfiguration, apiKeys []string) *apigatewayfern.ApiGatewaySecurity {
	if routes == nil {
		return nil
	}

	analysis := &apigatewayfern.ApiGatewaySecurity{
		HasWafIntegration:     false, // Would need additional API calls to determine
		HasCloudWatchLogging:  accessLogSettings != nil,
		HasThrottling:         false,
		OpenEndpoints:         0,
		HighRiskRoutes:        []string{},
		SecurityScore:         0.0,
		AuthenticationMethods: []apigatewayfern.AuthorizationType{},
		TlsVersions:           []apigatewayfern.SecurityPolicy{},
		CorsConfigured:        corsConfig != nil,
		ApiKeysRequired:       len(apiKeys) > 0,
	}

	// Track unique authentication methods
	authMethods := make(map[apigatewayfern.AuthorizationType]bool)

	// Analyze routes for security posture
	for _, route := range routes {
		if route == nil {
			continue
		}

		// Count open endpoints (no auth required)
		if route.Authorization == nil || *route.Authorization == apigatewayfern.AuthorizationTypeNone {
			analysis.OpenEndpoints++
			analysis.HighRiskRoutes = append(analysis.HighRiskRoutes, route.Method+" "+route.Path)
		}

		// Track authentication methods
		if route.Authorization != nil {
			authMethods[*route.Authorization] = true
		}

		// Check for throttling
		if route.Throttle != nil {
			analysis.HasThrottling = true
		}
	}

	// Convert auth methods map to slice
	for authType := range authMethods {
		analysis.AuthenticationMethods = append(analysis.AuthenticationMethods, authType)
	}

	// Extract TLS versions from certificates
	tlsVersions := make(map[apigatewayfern.SecurityPolicy]bool)
	for _, cert := range certificates {
		if cert != nil && cert.SecurityPolicy != nil {
			tlsVersions[*cert.SecurityPolicy] = true
		}
	}
	for tlsVersion := range tlsVersions {
		analysis.TlsVersions = append(analysis.TlsVersions, tlsVersion)
	}

	// Calculate security score (0-100)
	analysis.SecurityScore = calculateSecurityScore(analysis)

	return analysis
}

// calculateSecurityScore calculates a security score from 0-100 based on various factors
func calculateSecurityScore(analysis *apigatewayfern.ApiGatewaySecurity) float64 {
	if analysis == nil {
		return 0.0
	}

	score := 100.0

	// Deduct for open endpoints
	if analysis.OpenEndpoints > 0 {
		score -= float64(analysis.OpenEndpoints) * 10.0 // -10 points per open endpoint
	}

	// Add for logging
	if analysis.HasCloudWatchLogging {
		score += 10.0
	}

	// Add for throttling
	if analysis.HasThrottling {
		score += 10.0
	}

	// Add for CORS configuration
	if analysis.CorsConfigured {
		score += 5.0
	}

	// Add for API keys
	if analysis.ApiKeysRequired {
		score += 15.0
	}

	// Deduct for weak TLS versions
	for _, tlsVersion := range analysis.TlsVersions {
		if tlsVersion == apigatewayfern.SecurityPolicyTls10 {
			score -= 20.0 // TLS 1.0 is deprecated
		}
	}

	// Ensure score stays within bounds
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	return score
}
