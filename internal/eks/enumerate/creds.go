package eks

import (
	"context"
	"encoding/base64"
	"fmt"

	eksfern "github.com/Method-Security/methodaws/generated/go/eks"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func CredsEks(ctx context.Context, cfg aws.Config, clusterName string) (*eksfern.EksCredentialReport, error) {
	eksClient := eks.NewFromConfig(cfg)
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   "",
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}
	account := aws.ToString(accountID)

	clusterOutput, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}

	gen, err := token.NewGenerator(true, false)
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}
	opts := &token.GetTokenOptions{
		ClusterID: aws.ToString(clusterOutput.Cluster.Name),
	}
	tok, err := gen.GetWithOptions(ctx, opts)
	if err != nil {
		errors = append(errors, err.Error())
		return &eksfern.EksCredentialReport{
			Config: &eksfern.EksCredentialConfig{
				AccountId:   account,
				Regions:     []string{},
				ClusterName: clusterName,
			},
			Result: &eksfern.EksCredentialResult{},
			Errors: errors,
		}, nil
	}

	expiration := tok.Expiration
	caCert := aws.ToString(clusterOutput.Cluster.CertificateAuthority.Data)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(tok.Token))
	credInfo := eksfern.CredentialInfo{
		Url:        aws.ToString(clusterOutput.Cluster.Endpoint),
		Token:      encodedToken,
		CaCert:     &caCert,
		Expiration: &expiration,
		ClusterArn: fmt.Sprintf("arn:aws:eks:%s:%s:cluster/%s", cfg.Region, aws.ToString(accountID), clusterName),
	}

	report := eksfern.EksCredentialReport{
		Config: &eksfern.EksCredentialConfig{
			AccountId:   aws.ToString(accountID),
			Regions:     []string{cfg.Region},
			ClusterName: clusterName,
		},
		Result: &eksfern.EksCredentialResult{
			Credential: &credInfo,
		},
		Errors: errors,
	}
	return &report, nil
}
