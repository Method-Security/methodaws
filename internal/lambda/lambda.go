package lambda

import (
	"context"
	"fmt"
	"time"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

func parseLambdaArchitecture(architecture string) (methodaws.LambdaArchitecture, error) {
	switch architecture {
	case "x86_64":
		return methodaws.LambdaArchitectureX8664, nil
	case "arm64":
		return methodaws.LambdaArchitectureArm64, nil
	}
	return "", fmt.Errorf("%s is not a valid %T", architecture, methodaws.LambdaArchitecture(""))
}

func parseLambdaPackageType(packageType string) (methodaws.LambdaPackageType, error) {
	switch packageType {
	case "Zip":
		return methodaws.LambdaPackageTypeZip, nil
	case "Image":
		return methodaws.LambdaPackageTypeImage, nil
	}
	return "", fmt.Errorf("%s is not a valid %T", packageType, methodaws.LambdaPackageType(""))
}

func parseLambdaLoggingFormat(logFormat string) (methodaws.LambdaLoggingFormat, error) {
	switch logFormat {
	case "Text":
		return methodaws.LambdaLoggingFormatText, nil
	case "JSON":
		return methodaws.LambdaLoggingFormatJson, nil
	}
	return "", fmt.Errorf("%s is not a valid %T", logFormat, methodaws.LambdaLoggingFormat(""))
}

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
				architecture, err := parseLambdaArchitecture(string(architecture))
				if err != nil {
					return []*methodaws.LambdaFunction{}, err
				}
				lambdaArchitectures = append(lambdaArchitectures, architecture)
			}

			lambdaPackageType, err := parseLambdaPackageType(string(function.PackageType))
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
				logFormat, err := parseLambdaLoggingFormat(string(function.LoggingConfig.LogFormat))
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
