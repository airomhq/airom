package provenance

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// QuantizationType represents model weight precision format.
type QuantizationType string

const (
	QuantFP32     QuantizationType = "FP32"
	QuantFP16     QuantizationType = "FP16"
	QuantBF16     QuantizationType = "BF16"
	QuantGGUFQ4KM QuantizationType = "GGUF-Q4_K_M"
	QuantGGUFQ80  QuantizationType = "GGUF-Q8_0"
	QuantAWQ      QuantizationType = "AWQ-4BIT"
	QuantGPTQ     QuantizationType = "GPTQ-4BIT"
)

// ModelProvenanceNode captures the complete cryptographic and supply chain lineage for an AI model.
type ModelProvenanceNode struct {
	ModelID              string           `json:"model_id"`
	ModelName            string           `json:"model_name"`
	Version              string           `json:"version"`
	BaseModelID          string           `json:"base_model_id,omitempty"` // Upstream foundation model (e.g. meta-llama/Llama-3-8B)
	Author               string           `json:"author"`
	Organization         string           `json:"organization"`
	License              string           `json:"license"` // SPDX license identifier
	Quantization         QuantizationType `json:"quantization"`
	WeightsSHA256        string           `json:"weights_sha256"`
	TokenizerSHA256      string           `json:"tokenizer_sha256"`
	TrainingDatasetIDs   []string         `json:"training_dataset_ids"`
	TrainingCommitSHA    string           `json:"training_commit_sha"`
	CreatedTimestamp     time.Time        `json:"created_timestamp"`
	SignatureKeyID       string           `json:"signature_key_id"`
	AttestationSignature string           `json:"attestation_signature"`
	AttestationHash      string           `json:"attestation_hash"`
}

// ComputeAttestationHash calculates a deterministic SHA-256 fingerprint for the model provenance node.
func (n *ModelProvenanceNode) ComputeAttestationHash() string {
	raw := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s",
		n.ModelID, n.ModelName, n.Version, n.BaseModelID, n.Author,
		n.License, n.Quantization, n.WeightsSHA256, n.TokenizerSHA256,
		n.TrainingCommitSHA, n.CreatedTimestamp.UTC().Format(time.RFC3339))
	sum := sha256.Sum256([]byte(raw))
	n.AttestationHash = hex.EncodeToString(sum[:])
	return n.AttestationHash
}

// ProvenanceEdge connects a base foundation model to fine-tuned descendants or datasets.
type ProvenanceEdge struct {
	SourceModelID string `json:"source_model_id"`
	TargetModelID string `json:"target_model_id"`
	RelationType  string `json:"relation_type"` // e.g. "FINE_TUNED_FROM", "QUANTIZED_FROM", "DISTILLED_FROM"
}

// ProvenanceGraph encapsulates an enterprise lineage DAG of foundation models, fine-tunes, and datasets.
type ProvenanceGraph struct {
	GraphID     string                `json:"graph_id"`
	RootModelID string                `json:"root_model_id"`
	Nodes       []ModelProvenanceNode `json:"nodes"`
	Edges       []ProvenanceEdge      `json:"edges"`
	GeneratedAt time.Time             `json:"generated_at"`
	GraphHash   string                `json:"graph_hash"`
}

// ComputeGraphHash calculates a composite SHA-256 checksum over the entire provenance graph.
func (g *ProvenanceGraph) ComputeGraphHash() string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%s|%s\n", g.GraphID, g.RootModelID, g.GeneratedAt.UTC().Format(time.RFC3339))
	for _, n := range g.Nodes {
		_, _ = fmt.Fprintf(h, "%s:%s:%s\n", n.ModelID, n.WeightsSHA256, n.AttestationHash)
	}
	for _, e := range g.Edges {
		_, _ = fmt.Fprintf(h, "%s->%s(%s)\n", e.SourceModelID, e.TargetModelID, e.RelationType)
	}
	g.GraphHash = hex.EncodeToString(h.Sum(nil))
	return g.GraphHash
}

// ProvenanceVerificationResult reports the cryptographic verification of a model's supply chain.
type ProvenanceVerificationResult struct {
	ModelID              string    `json:"model_id"`
	Verified             bool      `json:"verified"`
	SignatureValid       bool      `json:"signature_valid"`
	LineageChainValid    bool      `json:"lineage_chain_valid"`
	WeightsChecksumValid bool      `json:"weights_checksum_valid"`
	SLSALevel            string    `json:"slsa_level"` // e.g. "SLSA_BUILD_LEVEL_3"
	Issues               []string  `json:"issues,omitempty"`
	VerifiedAt           time.Time `json:"verified_at"`
}
