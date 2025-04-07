package lambda

import (
	"context"
	"time"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func EnumerateLambdaForRegion(ctx context.Context, cfg aws.Config, region string) ([]*methodaws.LambdaFunction, error) {
	cfg.Region = region
	lambdaClient := lambda.NewFromConfig(cfg)
	paginator := lambda.NewListFunctionsPaginator(lambdaClient, &lambda.ListFunctionsInput{
		MaxItems: aws.Int32(100),
	})

	var functions []*methodaws.LambdaFunction
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(context.TODO())
		if err != nil {
			return []*methodaws.LambdaFunction{}, err
		}
		for _, function := range page.Functions {
			lastModified, err := time.Parse("2006-01-02T15:04:05.000-0700", *function.LastModified)
			if err != nil {
				return []*methodaws.LambdaFunction{}, err
			}

			lambdaArchitectures := []methodaws.LambdaArchitecture{}
			for _, architecture := range function.Architectures {
				architecture, err := methodaws.NewLambdaArchitectureFromString(string(architecture))
				if err != nil {
					return []*methodaws.LambdaFunction{}, err
				}
				lambdaArchitectures = append(lambdaArchitectures, architecture)
			}

			lambdaPackageType, err := methodaws.NewLambdaPackageTypeFromString(string(function.PackageType))
			if err != nil {
				return []*methodaws.LambdaFunction{}, err
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
				logFormat, err := methodaws.NewLambdaLoggingFormatFromString(string(function.LoggingConfig.LogFormat))
				if err != nil {
					return []*methodaws.LambdaFunction{}, err
				}
				loggingConfig = &methodaws.LambdaLoggingConfig{
					LogFormat: logFormat,
					LogGroup:  *function.LoggingConfig.LogGroup,
				}
			}

			functions = append(functions, &methodaws.LambdaFunction{
				Name:                 *function.FunctionName,
				Arn:                  *function.FunctionArn,
				Description:          *function.Description,
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
				CodeSha256:           *function.CodeSha256,
				Architectures:        lambdaArchitectures,
				Vpc:                  vpcConfig,
				LoggingConfig:        loggingConfig,
			})
		}
	}
	return functions, nil
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
		functions, err := EnumerateLambdaForRegion(ctx, cfg, region)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
		}
		report.Functions = append(report.Functions, functions...)
	}

	return report
}
