package provenance

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ProvenanceEngine maintains model supply chain lineage and validates cryptographic in-toto/SLSA attestations.
type ProvenanceEngine struct {
	mu        sync.RWMutex
	models    map[string]ModelProvenanceNode
	secretKey []byte
}

// NewProvenanceEngine creates a new ProvenanceEngine instance.
func NewProvenanceEngine(secretKey []byte) *ProvenanceEngine {
	if len(secretKey) == 0 {
		secretKey = []byte("airom-default-provenance-cosign-signing-key")
	}
	return &ProvenanceEngine{
		models:    make(map[string]ModelProvenanceNode),
		secretKey: secretKey,
	}
}

// RegisterModel cryptographically signs and indexes an AI model provenance node.
func (e *ProvenanceEngine) RegisterModel(node ModelProvenanceNode) (*ModelProvenanceNode, error) {
	if node.ModelID == "" {
		return nil, fmt.Errorf("model_id is required")
	}
	if node.WeightsSHA256 == "" {
		return nil, fmt.Errorf("weights_sha256 is required")
	}
	if node.CreatedTimestamp.IsZero() {
		node.CreatedTimestamp = time.Now().UTC()
	}

	node.ComputeAttestationHash()

	// Compute HMAC-SHA256 Cosign/Sigstore simulation signature
	mac := hmac.New(sha256.New, e.secretKey)
	mac.Write([]byte(node.AttestationHash))
	node.SignatureKeyID = "cosign-airom-key-v1"
	node.AttestationSignature = hex.EncodeToString(mac.Sum(nil))

	e.mu.Lock()
	e.models[node.ModelID] = node
	e.mu.Unlock()

	return &node, nil
}

// BuildLineageGraph traces upstream base models and downstream derivatives starting from rootModelID.
func (e *ProvenanceEngine) BuildLineageGraph(rootModelID string) (*ProvenanceGraph, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	root, ok := e.models[rootModelID]
	if !ok {
		return nil, fmt.Errorf("model not found: %s", rootModelID)
	}

	graph := &ProvenanceGraph{
		GraphID:     fmt.Sprintf("graph_%s", randHex(6)),
		RootModelID: rootModelID,
		Nodes:       make([]ModelProvenanceNode, 0),
		Edges:       make([]ProvenanceEdge, 0),
		GeneratedAt: time.Now().UTC(),
	}

	visited := make(map[string]bool)
	var collectLineage func(curr ModelProvenanceNode)

	collectLineage = func(curr ModelProvenanceNode) {
		if visited[curr.ModelID] {
			return
		}
		visited[curr.ModelID] = true
		graph.Nodes = append(graph.Nodes, curr)

		// Check upstream base model
		if curr.BaseModelID != "" {
			if parent, exists := e.models[curr.BaseModelID]; exists {
				graph.Edges = append(graph.Edges, ProvenanceEdge{
					SourceModelID: parent.ModelID,
					TargetModelID: curr.ModelID,
					RelationType:  "FINE_TUNED_FROM",
				})
				collectLineage(parent)
			}
		}

		// Check downstream fine-tunes derived from curr
		for _, candidate := range e.models {
			if candidate.BaseModelID == curr.ModelID && !visited[candidate.ModelID] {
				graph.Edges = append(graph.Edges, ProvenanceEdge{
					SourceModelID: curr.ModelID,
					TargetModelID: candidate.ModelID,
					RelationType:  "FINE_TUNED_FROM",
				})
				collectLineage(candidate)
			}
		}
	}

	collectLineage(root)
	graph.ComputeGraphHash()
	return graph, nil
}

// VerifyModelProvenance validates cryptographic signatures, weight checksums, and training lineage integrity.
func (e *ProvenanceEngine) VerifyModelProvenance(modelID string, actualWeightsSHA string) (*ProvenanceVerificationResult, error) {
	e.mu.RLock()
	node, ok := e.models[modelID]
	e.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("model not found in provenance registry: %s", modelID)
	}

	res := &ProvenanceVerificationResult{
		ModelID:              modelID,
		VerifiedAt:           time.Now().UTC(),
		SLSALevel:            "SLSA_BUILD_LEVEL_3",
		SignatureValid:       true,
		LineageChainValid:    true,
		WeightsChecksumValid: true,
		Issues:               make([]string, 0),
	}

	// 1. Verify Attestation Hash
	originalHash := node.AttestationHash
	recomputedHash := node.ComputeAttestationHash()
	if originalHash != recomputedHash {
		res.SignatureValid = false
		res.Issues = append(res.Issues, fmt.Sprintf("Attestation hash mismatch: expected %s, got %s", originalHash, recomputedHash))
	}

	// 2. Verify Cryptographic Signature
	mac := hmac.New(sha256.New, e.secretKey)
	mac.Write([]byte(recomputedHash))
	expectedSig := hex.EncodeToString(mac.Sum(nil))
	if node.AttestationSignature != expectedSig {
		res.SignatureValid = false
		res.Issues = append(res.Issues, "Cryptographic Cosign/Sigstore attestation signature verification failed.")
	}

	// 3. Verify Weights Checksum (if actualWeightsSHA provided)
	if actualWeightsSHA != "" && !strings.EqualFold(node.WeightsSHA256, actualWeightsSHA) {
		res.WeightsChecksumValid = false
		res.Issues = append(res.Issues, fmt.Sprintf("Model weights SHA-256 tampering detected: registry=%s, disk=%s",
			node.WeightsSHA256, actualWeightsSHA))
	}

	// 4. Verify Upstream Lineage Chain
	if node.BaseModelID != "" {
		e.mu.RLock()
		_, parentOk := e.models[node.BaseModelID]
		e.mu.RUnlock()
		if !parentOk {
			res.LineageChainValid = false
			res.Issues = append(res.Issues, fmt.Sprintf("Broken upstream lineage: Base model '%s' is unregistered or unverified.", node.BaseModelID))
		}
	}

	res.Verified = res.SignatureValid && res.LineageChainValid && res.WeightsChecksumValid
	return res, nil
}

// GenerateSLSAStatement creates an in-toto v1.0 / SLSA Provenance v1.0 predicate document.
func (e *ProvenanceEngine) GenerateSLSAStatement(node ModelProvenanceNode) (map[string]interface{}, error) {
	statement := map[string]interface{}{
		"_type": "https://in-toto.io/Statement/v1",
		"subject": []map[string]interface{}{
			{
				"name": node.ModelName,
				"digest": map[string]string{
					"sha256": node.WeightsSHA256,
				},
			},
		},
		"predicateType": "https://slsa.dev/provenance/v1",
		"predicate": map[string]interface{}{
			"buildDefinition": map[string]interface{}{
				"buildType": "https://airom.dev/slsa/ai-model-finetune/v1",
				"externalParameters": map[string]interface{}{
					"base_model":        node.BaseModelID,
					"quantization":      node.Quantization,
					"training_commit":   node.TrainingCommitSHA,
					"training_datasets": node.TrainingDatasetIDs,
					"spdx_license":      node.License,
				},
				"internalParameters": map[string]interface{}{
					"author":       node.Author,
					"organization": node.Organization,
				},
			},
			"runDetails": map[string]interface{}{
				"builder": map[string]string{
					"id": "https://airom.dev/provenance-engine/v1.0.0",
				},
				"metadata": map[string]string{
					"invocationId": fmt.Sprintf("inv_%s", randHex(8)),
					"startedOn":    node.CreatedTimestamp.Format(time.RFC3339),
				},
			},
		},
	}
	return statement, nil
}

// RenderProvenanceTree renders a hierarchical ASCII visual representation of the model lineage DAG.
func RenderProvenanceTree(g *ProvenanceGraph) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM MODEL SUPPLY CHAIN PROVENANCE & LINEAGE GRAPH\n")
	fmt.Fprintf(&sb, "  Graph ID: %s | Root Model: %s | Nodes: %d | Edges: %d\n",
		g.GraphID, g.RootModelID, len(g.Nodes), len(g.Edges))
	fmt.Fprintf(&sb, "  Graph Checksum: %s\n", g.GraphHash)
	fmt.Fprintf(&sb, "====================================================================================================\n\n")

	for i, node := range g.Nodes {
		prefix := "├──"
		if i == len(g.Nodes)-1 {
			prefix = "└──"
		}
		fmt.Fprintf(&sb, "%s [MODEL] %s (v%s)\n", prefix, node.ModelName, node.Version)
		fmt.Fprintf(&sb, "    │   • Model ID:       %s\n", node.ModelID)
		if node.BaseModelID != "" {
			fmt.Fprintf(&sb, "    │   • Base Model:     %s\n", node.BaseModelID)
		}
		fmt.Fprintf(&sb, "    │   • License:        %s | Precision: %s\n", node.License, node.Quantization)
		fmt.Fprintf(&sb, "    │   • Weights SHA:    %s\n", node.WeightsSHA256[:16]+"...")
		fmt.Fprintf(&sb, "    │   • Datasets:       %s\n", strings.Join(node.TrainingDatasetIDs, ", "))
		fmt.Fprintf(&sb, "    │   • Cosign Sig:     %s\n", node.AttestationSignature[:16]+"...")
		if i < len(g.Nodes)-1 {
			fmt.Fprintf(&sb, "    │\n")
		}
	}
	fmt.Fprintf(&sb, "\n====================================================================================================\n")
	return sb.String()
}
