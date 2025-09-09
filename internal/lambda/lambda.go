package lambda

import (
	//standard
	"context"
	"errors"
	"strings"
	"time"

	// generated
	lambdafern "github.com/Method-Security/methodaws/generated/go/lambda"
	// external
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

func parseLambdaFunctionConfiguration(ctx context.Context, function types.FunctionConfiguration, region string) (*lambdafern.LambdaFunction, error) {
	log := svc1log.FromContext(ctx)
	log.Info("Parsing Lambda function configuration",
		svc1log.SafeParam("functionName", function.FunctionName),
		svc1log.SafeParam("region", region))

	if function.LastModified == nil {
		return nil, errors.New("function LastModified is nil")
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05.000-0700", *function.LastModified)
	if err != nil {
		return nil, err
	}

	lambdaArchitectures := []lambdafern.LambdaArchitecture{}
	for _, architecture := range function.Architectures {
		architecture, err := lambdafern.NewLambdaArchitectureFromString(string(architecture))
		if err != nil {
			return nil, err
		}
		lambdaArchitectures = append(lambdaArchitectures, architecture)
	}

	lambdaPackageType, err := lambdafern.NewLambdaPackageTypeFromString(string(function.PackageType))
	if err != nil {
		return nil, err
	}

	var vpcConfig *lambdafern.LambdaVpcConfig
	if function.VpcConfig != nil {
		vpcConfig = &lambdafern.LambdaVpcConfig{
			VpcId:            *function.VpcConfig.VpcId,
			SubnetIds:        function.VpcConfig.SubnetIds,
			SecurityGroupIds: function.VpcConfig.SecurityGroupIds,
		}
	}

	var loggingConfig *lambdafern.LambdaLoggingConfig
	if function.LoggingConfig != nil {
		if function.LoggingConfig.LogGroup != nil {
			logFormat, err := lambdafern.NewLambdaLoggingFormatFromString(strings.ToUpper(string(function.LoggingConfig.LogFormat)))
			if err != nil {
				return nil, err
			}
			loggingConfig = &lambdafern.LambdaLoggingConfig{
				LogFormat: logFormat,
				LogGroup:  *function.LoggingConfig.LogGroup,
			}
		}
	}

	if function.FunctionName == nil {
		return nil, errors.New("function name is nil")
	}

	if function.FunctionArn == nil {
		return nil, errors.New("function arn is nil")
	}

	if function.Role == nil {
		return nil, errors.New("function role is nil")
	}

	if function.RevisionId == nil {
		return nil, errors.New("function revision id is nil")
	}

	if function.Handler == nil {
		return nil, errors.New("function handler is nil")
	}

	var result = &lambdafern.LambdaFunction{
		Name:                 *function.FunctionName,
		Arn:                  *function.FunctionArn,
		Description:          function.Description,
		Region:               region,
		RoleArn:              *function.Role,
		RevisionId:           *function.RevisionId,
		Runtime:              string(function.Runtime),
		Handler:              *function.Handler,
		CodeSizeInBytes:      function.CodeSize,
		PackageType:          lambdaPackageType,
		TimeoutInSeconds:     int(*function.Timeout),
		MemorySizeInMb:       int(*function.MemorySize),
		EphemeralStorageInMb: int(*function.EphemeralStorage.Size),
		LastModified:         lastModified,
		CodeSha256:           function.CodeSha256,
		Architectures:        lambdaArchitectures,
		Vpc:                  vpcConfig,
		LoggingConfig:        loggingConfig,
	}
	return result, nil
}

func enumerateLambdaForRegion(ctx context.Context, awsConfig aws.Config, region string) ([]*lambdafern.LambdaFunction, []error) {
	log := svc1log.FromContext(ctx)
	log.Info("Enumerating Lambda functions for region", svc1log.SafeParam("region", region))

	awsConfig.Region = region
	lambdaClient := lambda.NewFromConfig(awsConfig)
	paginator := lambda.NewListFunctionsPaginator(lambdaClient, &lambda.ListFunctionsInput{
		MaxItems: aws.Int32(50),
	})

	var functions []*lambdafern.LambdaFunction
	var errors []error
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			log.Error("Failed to get next page of Lambda functions",
				svc1log.SafeParam("region", region),
				svc1log.Stacktrace(err))
			// failed to page so just return an empty list and the error
			return []*lambdafern.LambdaFunction{}, append(errors, err)
		}
		for _, function := range page.Functions {
			parsedFunction, err := parseLambdaFunctionConfiguration(ctx, function, region)
			if err != nil {
				errors = append(errors, err)
			} else {
				functions = append(functions, parsedFunction)
			}
		}
	}
	return functions, errors
}

func EnumerateLambda(ctx context.Context, awsConfig aws.Config, config lambdafern.LambdaEnumerateConfig) *lambdafern.LambdaEnumerateReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting Lambda enumeration",
		svc1log.SafeParam("regionsCount", len(config.Regions)),
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &lambdafern.LambdaEnumerateReport{
		Config: &config,
		Result: &lambdafern.LambdaEnumerateResult{},
	}

	var allFunctions []*lambdafern.LambdaFunction
	var allErrors []string

	for _, region := range config.Regions {
		log.Info("Processing Lambda functions in region", svc1log.SafeParam("region", region))
		functions, errs := enumerateLambdaForRegion(ctx, awsConfig, region)
		allFunctions = append(allFunctions, functions...)
		for _, err := range errs {
			allErrors = append(allErrors, err.Error())
		}
	}

	// Populate report
	if len(allFunctions) > 0 {
		report.Result.Functions = allFunctions
	}
	report.Errors = allErrors
	return report
}
