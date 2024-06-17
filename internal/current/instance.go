package current

import (
	"context"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
)

// AWSResource contains the instance identity document, hostname, public IP, and public hostname of the current AWS instance.
// It is used to represent the current state of the instance.
type AWSResource struct {
	IdentityDocument imds.InstanceIdentityDocument `json:"identityDocument" yaml:"identityDocument"`
	Hostname         string                        `json:"hostname" yaml:"hostname"`
	PublicIP         string                        `json:"publicIp" yaml:"publicIp"`
	PublicHostname   string                        `json:"publicHostname" yaml:"publicHostname"`
}

// AWSResourceReport contains the AWSResource and any errors that occurred during the execution of the
// `methodaws current instance` subcommand.
type AWSResourceReport struct {
	Resource AWSResource `json:"resource" yaml:"resource"`
	Errors   []string    `json:"errors" yaml:"errors"`
}

func getHostname(ctx context.Context, client *imds.Client) (string, error) {
	hostnameMetadata, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "hostname",
	})
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(hostnameMetadata.Content)
	_ = hostnameMetadata.Content.Close()
	if err != nil {
		return "", err
	}
	hostname := strings.TrimSpace(string(content))
	return hostname, nil
}

func getPublicIP(ctx context.Context, client *imds.Client) (string, error) {
	publicIPMetadata, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "public-ipv4",
	})
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(publicIPMetadata.Content)
	_ = publicIPMetadata.Content.Close()
	if err != nil {
		return "", err
	}
	publicIP := strings.TrimSpace(string(content))
	return publicIP, nil
}

func getPublicHostname(ctx context.Context, client *imds.Client) (string, error) {
	publicHostnameMetadata, err := client.GetMetadata(ctx, &imds.GetMetadataInput{
		Path: "public-hostname",
	})
	if err != nil {
		return "", err
	}
	content, err := io.ReadAll(publicHostnameMetadata.Content)
	_ = publicHostnameMetadata.Content.Close()
	if err != nil {
		return "", err
	}
	publicHostname := strings.TrimSpace(string(content))
	return publicHostname, nil
}

// InstanceDetails is responsible for gathering the instance identity document, hostname, public IP, and public hostname
// of the current AWS instance. It returns an AWSResourceReport struct that contains any non-fatal errors that occurred
// during the execution of the subcommand.
func InstanceDetails(ctx context.Context, cfg aws.Config) (AWSResourceReport, error) {
	client := imds.NewFromConfig(cfg)

	resource := AWSResource{}
	errors := []string{}

	instanceIdentityOutput, err := client.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		errors = append(errors, err.Error())
	}

	resource.IdentityDocument = instanceIdentityOutput.InstanceIdentityDocument

	hostname, err := getHostname(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
	}
	resource.Hostname = hostname

	publicIP, err := getPublicIP(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
	}
	resource.PublicIP = publicIP

	publicHostname, err := getPublicHostname(ctx, client)
	if err != nil {
		errors = append(errors, err.Error())
	}
	resource.PublicHostname = publicHostname

	return AWSResourceReport{
		Resource: resource,
		Errors:   errors,
	}, nil
}
