package apigateway

import (
	"context"
	"fmt"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigateway/types"
)

func EnumerateAPIGateway(ctx context.Context, cfg aws.Config, regions []string) (report methodaws.ApiGatewayReport, err error) {
	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		return methodaws.ApiGatewayReport{
			AccountId: aws.ToString(accountID),
			Apis:      []*methodaws.ApiGatewayApi{},
			Errors:    []string{err.Error()},
		}, err
	}

	apiGatewayReport := methodaws.ApiGatewayReport{
		AccountId: aws.ToString(accountID),
		Apis:      []*methodaws.ApiGatewayApi{},
		Errors:    []string{},
	}

	for _, region := range regions {
		err := EnumerateAPIGatewayForRegion(ctx, cfg, &apiGatewayReport, region)
		if err != nil {
			return report, err
		}
	}

	return apiGatewayReport, nil
}

func EnumerateAPIGatewayForRegion(ctx context.Context, cfg aws.Config, report *methodaws.ApiGatewayReport, region string) (err error) {
	cfg.Region = region
	client := apigateway.NewFromConfig(cfg)
	paginator := apigateway.NewGetRestApisPaginator(client, &apigateway.GetRestApisInput{})

	for paginator.HasMorePages() {

		result, err := paginator.NextPage(ctx)
		if err != nil {
			report.Errors = append(report.Errors, err.Error())
			break
		}

		for _, api := range result.Items {
			stages, err := client.GetStages(ctx, &apigateway.GetStagesInput{RestApiId: api.Id})
			if err != nil {
				report.Errors = append(report.Errors, err.Error())
			}

			// stage name is needed to construct the base url path
			// base url is in the following format
			// https://<apiId>.execute-api.<region>.amazonaws.com/<stageName>
			for _, stage := range stages.Item {
				baseURL := fmt.Sprintf("https://%s.execute-api.%s.amazonaws.com/%s", *api.Id, region, *stage.StageName)
				apis := []*methodaws.RestApiPath{}
				resources, err := client.GetResources(ctx, &apigateway.GetResourcesInput{RestApiId: api.Id})
				if err != nil {
					report.Errors = append(report.Errors, err.Error())
				}

				for _, resource := range resources.Items {
					for name := range resource.ResourceMethods {
						details, err := client.GetMethod(ctx, &apigateway.GetMethodInput{RestApiId: api.Id, ResourceId: resource.Id, HttpMethod: &name})
						if err != nil {
							report.Errors = append(report.Errors, err.Error())
						}

						var typeIntegration methodaws.Integration

						switch details.MethodIntegration.Type {
						case types.IntegrationTypeHttp:
							typeIntegration = *methodaws.NewIntegrationFromHttp(&methodaws.HttpIntegration{Uri: *details.MethodIntegration.Uri})
						case types.IntegrationTypeAws:
							typeIntegration = *methodaws.NewIntegrationFromAws(&methodaws.AwsIntegration{Arn: *details.MethodIntegration.Uri})
						case types.IntegrationTypeHttpProxy:
							typeIntegration = *methodaws.NewIntegrationFromHttpProxy(&methodaws.HttpProxyIntegration{Uri: *details.MethodIntegration.Uri})
						case types.IntegrationTypeAwsProxy:
							typeIntegration = *methodaws.NewIntegrationFromAwsProxy(&methodaws.AwsProxyIntegration{Arn: *details.MethodIntegration.Uri})
						case types.IntegrationTypeMock:
							typeIntegration = *methodaws.NewIntegrationFromMock(&methodaws.MockIntegration{})
						default:
							continue
						}

						restAPIPath := methodaws.RestApiPath{
							Path:        *resource.Path,
							Method:      name,
							Integration: &typeIntegration,
						}
						apis = append(apis, &restAPIPath)
					}
				}

				restAPI := methodaws.RestApi{
					BaseUrl:     baseURL,
					Region:      region,
					CreatedTime: *api.CreatedDate,
					Name:        *api.Name,
					Decription:  api.Description,
					Stage:       *stage.StageName,
					Paths:       apis,
				}
				gatewayAPI := methodaws.NewApiGatewayApiFromRest(&restAPI)
				report.Apis = append(report.Apis, gatewayAPI)
			}
		}
	}

	return nil
}
