package current

import (
	// Standard
	"encoding/json"
	"fmt"
	"net/url"

	// Generated
	iam "github.com/Method-Security/methodaws/generated/go/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// convertPolicyVersionToFern converts AWS IAM PolicyVersion to Fern DecodedPolicyVersion
func convertPolicyVersionToFern(version *types.PolicyVersion) (*iam.DecodedPolicyVersion, error) {
	if version == nil {
		return nil, fmt.Errorf("policy version is nil")
	}

	decodedVersion := &iam.DecodedPolicyVersion{
		CreateDate:       version.CreateDate,
		IsDefaultVersion: &version.IsDefaultVersion,
		VersionId:        version.VersionId,
	}

	// Decode and format policy document
	if version.Document != nil {
		decodedDoc, err := url.QueryUnescape(*version.Document)
		if err != nil {
			return nil, fmt.Errorf("failed to decode policy document: %w", err)
		}

		// Pretty format the JSON
		var jsonDoc interface{}
		if json.Unmarshal([]byte(decodedDoc), &jsonDoc) == nil {
			if prettyJSON, err := json.MarshalIndent(jsonDoc, "", "  "); err == nil {
				prettyJSONStr := string(prettyJSON)
				decodedVersion.Document = &prettyJSONStr
			} else {
				decodedVersion.Document = &decodedDoc
			}
		} else {
			decodedVersion.Document = &decodedDoc
		}
	}

	return decodedVersion, nil
}
