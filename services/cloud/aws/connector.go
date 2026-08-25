package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Connector scans and translates AWS AI services into canonical AIBOM models.
type Connector struct {
	mu sync.RWMutex
}

// NewConnector constructs a new AWS cloud connector.
func NewConnector() *Connector {
	return &Connector{}
}

// CompileAIBOM builds an *airom.Inventory from discovered AWS AI resources.
func (c *Connector) CompileAIBOM(accountID, region string, bedrock []BedrockModelSpec, sagemaker []SageMakerEndpointSpec) *DiscoveryScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()

	now := time.Now().UTC()
	inv := &airom.Inventory{
		SchemaVersion: "1.0",
		Timestamp:     now,
		Source: airom.SourceInfo{
			Kind:   "aws_cloud",
			Target: fmt.Sprintf("arn:aws:iam::%s:root/%s", accountID, region),
		},
		Tool: airom.ToolInfo{
			Name:    "airom-aws-connector",
			Version: "1.0.0",
		},
	}

	var comps []airom.Component
	var rels []airom.Relationship

	// 1. Ingest Bedrock Models
	for _, bm := range bedrock {
		cleanID := sanitizeID(fmt.Sprintf("aws-bedrock-%s-%s", bm.Region, bm.ModelID))
		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindHostedLLM,
			Name:       bm.ModelName,
			Provider:   airom.KnownString(bm.ProviderName),
			Confidence: 1.0,
			PURL:       fmt.Sprintf("pkg:bedrock/%s/%s@%s", strings.ToLower(bm.ProviderName), bm.ModelID, bm.Region),
		}

		if len(bm.InputModalities) > 0 {
			comp.Props = []airom.KV{
				{Name: "aws.region", Value: bm.Region},
				{Name: "aws.account", Value: bm.AccountID},
				{Name: "aws.modalities.input", Value: strings.Join(bm.InputModalities, ",")},
			}
		}

		comps = append(comps, comp)
	}

	// 2. Ingest SageMaker Endpoints
	for _, sm := range sagemaker {
		cleanID := sanitizeID(fmt.Sprintf("aws-sagemaker-%s-%s", region, sm.EndpointName))
		comp := airom.Component{
			ID:         airom.ID(cleanID),
			Kind:       airom.KindHostedLLM,
			Name:       sm.EndpointName,
			Provider:   airom.KnownString("AWS-SageMaker"),
			Confidence: 0.95,
			PURL:       fmt.Sprintf("pkg:sagemaker/%s/%s", region, sm.EndpointName),
			Props: []airom.KV{
				{Name: "aws.sagemaker.instance", Value: sm.InstanceType},
				{Name: "aws.sagemaker.image", Value: sm.PrimaryContainerImage},
				{Name: "aws.sagemaker.s3_model", Value: sm.ModelArtifactS3URI},
				{Name: "aws.sagemaker.kms_key", Value: sm.KMSEncryptionARN},
			},
		}

		comps = append(comps, comp)

		// Model artifact relationship if S3 URI exists
		if sm.ModelArtifactS3URI != "" {
			artifactID := airom.ID(sanitizeID(fmt.Sprintf("s3-artifact-%s", sm.ModelArtifactS3URI)))
			artifactComp := airom.Component{
				ID:         artifactID,
				Kind:       airom.KindLocalModelFile,
				Name:       sm.ModelArtifactS3URI,
				Provider:   airom.KnownString("Amazon-S3"),
				Confidence: 1.0,
			}
			comps = append(comps, artifactComp)

			rels = append(rels, airom.Relationship{
				From: comp.ID,
				To:   artifactID,
				Type: airom.RelUses,
			})
		}
	}

	inv.Components = comps
	inv.Relationships = rels

	return &DiscoveryScanResult{
		AccountID:          accountID,
		Region:             region,
		ScannedAt:          now,
		BedrockModels:      bedrock,
		SageMakerEndpoints: sagemaker,
		Inventory:          inv,
	}
}

func sanitizeID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	short := hex.EncodeToString(h[:4])
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(raw))
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%s-%s", clean, short)
}
