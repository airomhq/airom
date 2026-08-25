package aws

import (
	"strings"
	"testing"
)

func TestQA_AdversarialSpecialCharactersInNames(t *testing.T) {
	connector := NewConnector()

	bedrock := []BedrockModelSpec{
		{
			ModelID:      "anthropic.claude'; DROP TABLE bedrock_models; --",
			ModelName:    "<script>alert('xss')</script>",
			ProviderName: "Anthropic/Unicode/🚀",
			Region:       "us-east-1",
		},
	}

	sagemaker := []SageMakerEndpointSpec{
		{
			EndpointName:       "../../../../etc/shadow",
			ModelArtifactS3URI: "s3://bucket/\x00\xff/malicious.tar.gz",
		},
	}

	res := connector.CompileAIBOM("123456789012", "us-east-1", bedrock, sagemaker)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected robust compilation on adversarial names")
	}

	for _, c := range res.Inventory.Components {
		if strings.Contains(string(c.ID), " ") || strings.Contains(string(c.ID), ";") {
			t.Errorf("component ID was not properly sanitized: %s", c.ID)
		}
	}
}

func TestQA_AdversarialEmptyStringsAndZeroCounts(t *testing.T) {
	connector := NewConnector()

	bedrock := []BedrockModelSpec{{ModelID: "", ModelName: "", ProviderName: ""}}
	sagemaker := []SageMakerEndpointSpec{{EndpointName: "", InstanceType: "", ModelArtifactS3URI: ""}}

	res := connector.CompileAIBOM("", "", bedrock, sagemaker)
	if res == nil || res.Inventory == nil {
		t.Fatalf("expected valid inventory on empty fields")
	}
	if len(res.Inventory.Components) != 2 {
		t.Errorf("expected 2 components, got %d", len(res.Inventory.Components))
	}
}
