package eks

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Method-Security/methodaws/internal/sts"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func AuthenticateEks(ctx context.Context, cfg aws.Config, clusterName string) (*AWSResourceReport, error) {
	eksClient := eks.NewFromConfig(cfg)
	resources := AWSResources{}
	errors := []string{}

	accountID, err := sts.GetAccountID(ctx, cfg)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	clusterOutput, err := eksClient.DescribeCluster(ctx, &eks.DescribeClusterInput{
		Name: aws.String(clusterName),
	})
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	gen, err := token.NewGenerator(true, false)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}
	opts := &token.GetTokenOptions{
		ClusterID: aws.ToString(clusterOutput.Cluster.Name),
	}
	tok, err := gen.GetWithOptions(opts)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	ca, err := base64.StdEncoding.DecodeString(aws.ToString(clusterOutput.Cluster.CertificateAuthority.Data))
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    server: %s
    certificate-authority-data: %s
  name: %[3]s
contexts:
- context:
    cluster: %[3]s
    user: %[3]s
  name: %[3]s
current-context: %[3]s
users:
- name: %[3]s
  user:
    token: %s
`, aws.ToString(clusterOutput.Cluster.Endpoint), base64.StdEncoding.EncodeToString(ca), clusterName, tok.Token)

	kubeconfigPath := filepath.Join(".kube", "config")

	err = os.MkdirAll(filepath.Dir(kubeconfigPath), 0755)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	err = os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0644)
	if err != nil {
		errors = append(errors, err.Error())
		return &AWSResourceReport{
			AccountID: aws.ToString(accountID),
			Resources: resources,
			Errors:    errors,
		}, nil
	}

	report := AWSResourceReport{
		AccountID: aws.ToString(accountID),
		Errors:    errors,
	}
	return &report, nil
}
