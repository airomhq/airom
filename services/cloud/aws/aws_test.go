package aws

import (
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

func TestAWS_BedrockAndSageMakerAIBOM(t *testing.T) {
	connector := NewConnector()

	bedrock := []BedrockModelSpec{
		{
			ModelID:         "anthropic.claude-3-5-sonnet-20240620-v1:0",
			ModelName:       "Claude 3.5 Sonnet",
			ProviderName:    "Anthropic",
			InputModalities: []string{"TEXT", "IMAGE"},
			Region:          "us-east-1",
			AccountID:       "123456789012",
		},
	}

	sagemaker := []SageMakerEndpointSpec{
		{
			EndpointARN:           "arn:aws:sagemaker:us-east-1:123456789012:endpoint/llama-3-70b-prod",
			EndpointName:          "llama-3-70b-prod",
			EndpointStatus:        "InService",
			InstanceType:          "ml.g5.12xlarge",
			InitialInstanceCount:  2,
			PrimaryContainerImage: "763104351884.dkr.ecr.us-east-1.amazonaws.com/djl-inference:0.28.0-deepspeed0.12.6-cu121",
			ModelArtifactS3URI:    "s3://enterprise-ai-models/llama-3-70b-instruct.tar.gz",
			KMSEncryptionARN:      "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012",
			CreatedAt:             time.Now().UTC(),
		},
	}

	res := connector.CompileAIBOM("123456789012", "us-east-1", bedrock, sagemaker)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected non-nil discovery scan result and inventory")
	}

	// 1 Bedrock model + 1 SageMaker endpoint + 1 S3 model artifact = 3 components
	if len(res.Inventory.Components) != 3 {
		t.Errorf("expected 3 components, got %d", len(res.Inventory.Components))
	}

	// 1 relationship between SageMaker endpoint and S3 artifact
	if len(res.Inventory.Relationships) != 1 {
		t.Errorf("expected 1 relationship, got %d", len(res.Inventory.Relationships))
	}

	if res.Inventory.Relationships[0].Type != airom.RelUses {
		t.Errorf("expected RelUses relationship, got %s", res.Inventory.Relationships[0].Type)
	}
}

func TestAWS_EmptyScanResult(t *testing.T) {
	connector := NewConnector()
	res := connector.CompileAIBOM("123456789012", "us-west-2", nil, nil)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected valid empty inventory")
	}
	if len(res.Inventory.Components) != 0 {
		t.Errorf("expected 0 components, got %d", len(res.Inventory.Components))
	}
}
