package lambda

import (
	"context"
	"errors"
	"time"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	"github.com/aws/aws-sdk-go-v2/service/lambda/types"
)

func parseLambdaFunctionConfiguration(function types.FunctionConfiguration, region string) (*methodaws.LambdaFunction, error) {
	if function.LastModified == nil {
		return nil, errors.New("function LastModified is nil")
	}

	lastModified, err := time.Parse("2006-01-02T15:04:05.000-0700", *function.LastModified)
	if err != nil {
		return nil, err
	}

	lambdaArchitectures := []methodaws.LambdaArchitecture{}
	for _, architecture := range function.Architectures {
		architecture, err := methodaws.NewLambdaArchitectureFromString(string(architecture))
		if err != nil {
			return nil, err
		}
		lambdaArchitectures = append(lambdaArchitectures, architecture)
	}

	lambdaPackageType, err := methodaws.NewLambdaPackageTypeFromString(string(function.PackageType))
	if err != nil {
		return nil, err
	}

	var vpcConfig *methodaws.LambdaVpcConfig
	if function.VpcConfig != nil {
		vpcConfig = &methodaws.LambdaVpcConfig{
			VpcId:            *function.VpcConfig.VpcId,
			SubnetIds:        function.VpcConfig.SubnetIds,
			SecurityGroupIds: function.VpcConfig.SecurityGroupIds,
		}
	}

	var loggingConfig *methodaws.LambdaLoggingConfig
	if function.LoggingConfig != nil {
		if function.LoggingConfig.LogGroup != nil {
			logFormat, err := methodaws.NewLambdaLoggingFormatFromString(string(function.LoggingConfig.LogFormat))
			if err != nil {
				return nil, err
			}
			loggingConfig = &methodaws.LambdaLoggingConfig{
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

	var result = &methodaws.LambdaFunction{
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

func enumerateLambdaForRegion(ctx context.Context, cfg aws.Config, region string) ([]*methodaws.LambdaFunction, []error) {
	cfg.Region = region
	lambdaClient := lambda.NewFromConfig(cfg)
	paginator := lambda.NewListFunctionsPaginator(lambdaClient, &lambda.ListFunctionsInput{
		MaxItems: aws.Int32(50),
	})

	var functions []*methodaws.LambdaFunction
	var errors []error
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			// failed to page so just return an empty list and the error
			return []*methodaws.LambdaFunction{}, append(errors, err)
		}
		for _, function := range page.Functions {
			parsedFunction, err := parseLambdaFunctionConfiguration(function, region)
			if err != nil {
				errors = append(errors, err)
			} else {
				functions = append(functions, parsedFunction)
			}
		}
	}
	return functions, errors
}

func EnumerateLambda(ctx context.Context, cfg aws.Config, regions []string) methodaws.LambdaReport {
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return methodaws.LambdaReport{
			AccountId: aws.ToString(accountID),
			Functions: []*methodaws.LambdaFunction{},
			Errors:    []string{err.Error()},
		}
	}

	report := methodaws.LambdaReport{
		AccountId: aws.ToString(accountID),
		Functions: []*methodaws.LambdaFunction{},
		Errors:    []string{},
	}

	for _, region := range regions {
		functions, errs := enumerateLambdaForRegion(ctx, cfg, region)
		report.Functions = append(report.Functions, functions...)
		for _, err := range errs {
			report.Errors = append(report.Errors, err.Error())
		}
	}

	return report
}
