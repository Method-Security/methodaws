package eks

import (
	"context"
	"encoding/base64"

	methodaws "github.com/Method-Security/methodaws/generated/go"
	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func CredsEks(ctx context.Context, cfg aws.Config, clusterName string) (*methodaws.CredentialReport, error) {
	eksClient := eks.NewFromConfig(cfg)
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &methodaws.CredentialReport{
			AccountId:   "",
			ClusterName: clusterName,
			Errors:      errors,
		}, nil
	}
	account := aws.ToString(accountID)

	clusterOutput, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		errors = append(errors, err.Error())
		return &methodaws.CredentialReport{
			AccountId:   account,
			ClusterName: clusterName,
			Errors:      errors,
		}, nil
	}

	gen, err := token.NewGenerator(true, false)
	if err != nil {
		errors = append(errors, err.Error())
		return &methodaws.CredentialReport{
			AccountId:   account,
			ClusterName: clusterName,
			Errors:      errors,
		}, nil
	}
	opts := &token.GetTokenOptions{
		ClusterID: aws.ToString(clusterOutput.Cluster.Name),
	}
	tok, err := gen.GetWithOptions(opts)
	if err != nil {
		errors = append(errors, err.Error())
		return &methodaws.CredentialReport{
			AccountId:   account,
			ClusterName: clusterName,
			Errors:      errors,
		}, nil
	}

	expiration := tok.Expiration
	caCert := aws.ToString(clusterOutput.Cluster.CertificateAuthority.Data)
	encodedToken := base64.StdEncoding.EncodeToString([]byte(tok.Token))
	credInfo := methodaws.CredentialInfo{
		Url:        aws.ToString(clusterOutput.Cluster.Endpoint),
		Token:      encodedToken,
		CaCert:     &caCert,
		Expiration: &expiration,
	}

	report := methodaws.CredentialReport{
		AccountId:   aws.ToString(accountID),
		ClusterName: clusterName,
		Credential:  &credInfo,
		Errors:      errors,
	}
	return &report, nil
}
