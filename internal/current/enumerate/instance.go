package current

import (
	"context"
	"io"
	"strings"

	currentfern "github.com/Method-Security/methodaws/generated/go/current"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	svc1log "github.com/palantir/witchcraft-go-logging/wlog/svclog/svc1log"
)

// EnumerateCurrentInstance enumerates the current AWS instance details
func EnumerateCurrentInstance(ctx context.Context, awsConfig aws.Config, config currentfern.CurrentInstanceConfig) *currentfern.CurrentInstanceReport {
	log := svc1log.FromContext(ctx)
	log.Info("Starting current instance enumeration",
		svc1log.SafeParam("accountId", config.AccountId))

	// Initialize report
	report := &currentfern.CurrentInstanceReport{
		Config: &config,
		Result: &currentfern.CurrentInstanceResult{
			Resource: &currentfern.CurrentInstanceResource{},
		},
	}

	var allErrors []string

	client := imds.NewFromConfig(awsConfig)
	resource := &currentfern.CurrentInstanceResource{}

	// Get instance identity document
	log.Info("Getting instance identity document")
	instanceIdentityOutput, err := client.GetInstanceIdentityDocument(ctx, &imds.GetInstanceIdentityDocumentInput{})
	if err != nil {
		allErrors = append(allErrors, err.Error())
	} else {
		resource.IdentityDocument = convertInstanceIdentityDocument(instanceIdentityOutput.InstanceIdentityDocument)
	}

	// Get hostname
	log.Info("Getting hostname")
	hostname, err := getHostname(ctx, client)
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}
	resource.Hostname = hostname

	// Get public IP
	log.Info("Getting public IP")
	publicIP, err := getPublicIP(ctx, client)
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}
	resource.PublicIp = publicIP

	// Get public hostname
	log.Info("Getting public hostname")
	publicHostname, err := getPublicHostname(ctx, client)
	if err != nil {
		allErrors = append(allErrors, err.Error())
	}
	resource.PublicHostname = publicHostname

	// Populate report
	report.Result.Resource = resource

	if len(allErrors) > 0 {
		report.Errors = allErrors
	}

	log.Info("Completed current instance enumeration",
		svc1log.SafeParam("totalErrors", len(allErrors)))

	return report
}

// convertInstanceIdentityDocument converts AWS IMDS InstanceIdentityDocument to Fern format
func convertInstanceIdentityDocument(doc imds.InstanceIdentityDocument) *currentfern.InstanceIdentityDocument {
	return &currentfern.InstanceIdentityDocument{
		AccountId:               doc.AccountID,
		InstanceId:              doc.InstanceID,
		Architecture:            &doc.Architecture,
		AvailabilityZone:        &doc.AvailabilityZone,
		BillingProducts:         doc.BillingProducts,
		DevpayProductCodes:      doc.DevpayProductCodes,
		MarketplaceProductCodes: doc.MarketplaceProductCodes,
		ImageId:                 &doc.ImageID,
		InstanceType:            &doc.InstanceType,
		KernelId:                &doc.KernelID,
		PendingTime:             &doc.PendingTime,
		PrivateIp:               &doc.PrivateIP,
		RamdiskId:               &doc.RamdiskID,
		Region:                  &doc.Region,
		Version:                 &doc.Version,
	}
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
