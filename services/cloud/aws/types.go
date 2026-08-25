// Package aws provides automated cloud discovery and AIBOM generation
// for AWS Bedrock foundation models, SageMaker endpoints, and custom model packages.
package aws

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// ResourceType identifies the AWS AI service resource.
type ResourceType string

const (
	TypeBedrockFoundation ResourceType = "AWS::Bedrock::FoundationModel"
	TypeBedrockCustom     ResourceType = "AWS::Bedrock::CustomModel"
	TypeSageMakerEndpoint ResourceType = "AWS::SageMaker::Endpoint"
	TypeSageMakerPackage  ResourceType = "AWS::SageMaker::ModelPackage"
)

// BedrockModelSpec defines an AWS Bedrock foundation or custom model deployment.
type BedrockModelSpec struct {
	ModelID          string            `json:"modelId"`          // e.g. "anthropic.claude-3-5-sonnet-20240620-v1:0"
	ModelName        string            `json:"modelName"`        // e.g. "Claude 3.5 Sonnet"
	ProviderName     string            `json:"providerName"`     // e.g. "Anthropic"
	InputModalities  []string          `json:"inputModalities"`  // e.g. ["TEXT", "IMAGE"]
	OutputModalities []string          `json:"outputModalities"` // e.g. ["TEXT"]
	Customizations   []string          `json:"customizations"`   // e.g. ["FINE_TUNING"]
	KMSEncryptionARN string            `json:"kmsEncryptionArn,omitempty"`
	Region           string            `json:"region"`
	AccountID        string            `json:"accountId"`
	Tags             map[string]string `json:"tags,omitempty"`
}

// SageMakerEndpointSpec defines an active AWS SageMaker real-time or serverless endpoint.
type SageMakerEndpointSpec struct {
	EndpointARN           string            `json:"endpointArn"`
	EndpointName          string            `json:"endpointName"`
	EndpointStatus        string            `json:"endpointStatus"` // e.g. "InService"
	InstanceType          string            `json:"instanceType"`   // e.g. "ml.g5.12xlarge"
	InitialInstanceCount  int               `json:"initialInstanceCount"`
	PrimaryContainerImage string            `json:"primaryContainerImage"`
	ModelArtifactS3URI    string            `json:"modelArtifactS3Uri"`
	KMSEncryptionARN      string            `json:"kmsEncryptionArn,omitempty"`
	CreatedAt             time.Time         `json:"createdAt"`
	Tags                  map[string]string `json:"tags,omitempty"`
}

// DiscoveryScanResult represents the inventory produced by an AWS cloud scan.
type DiscoveryScanResult struct {
	AccountID          string                  `json:"accountId"`
	Region             string                  `json:"region"`
	ScannedAt          time.Time               `json:"scannedAt"`
	BedrockModels      []BedrockModelSpec      `json:"bedrockModels"`
	SageMakerEndpoints []SageMakerEndpointSpec `json:"sagemakerEndpoints"`
	Inventory          *airom.Inventory        `json:"inventory"`
}
