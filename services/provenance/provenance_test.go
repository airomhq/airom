package provenance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProvenance_Register_And_BuildGraph(t *testing.T) {
	engine := NewProvenanceEngine(nil)

	// 1. Foundation Base Model
	baseModel := ModelProvenanceNode{
		ModelID:           "meta-llama/Llama-3-8B",
		ModelName:         "Llama-3-8B-Base",
		Version:           "1.0.0",
		Author:            "Meta AI",
		Organization:      "Meta Platforms Inc.",
		License:           "Llama-3-Community",
		Quantization:      QuantBF16,
		WeightsSHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		TokenizerSHA256:   "ca978112ca1bbdcafac231b39a23dc4da786081cd1e14eed6da7e60742137682",
		TrainingCommitSHA: "abcdef1234567890abcdef1234567890abcdef12",
		CreatedTimestamp:  time.Now().UTC(),
	}
	_, err := engine.RegisterModel(baseModel)
	if err != nil {
		t.Fatalf("failed to register base model: %v", err)
	}

	// 2. Fine-Tuned Model
	fineTuned := ModelProvenanceNode{
		ModelID:            "enterprise/llama3-legal-advisor",
		ModelName:          "Enterprise Legal Advisor Llama-3",
		Version:            "1.2.0",
		BaseModelID:        "meta-llama/Llama-3-8B",
		Author:             "Enterprise AI Lab",
		Organization:       "Enterprise Corp",
		License:            "Proprietary-Commercial",
		Quantization:       QuantFP16,
		WeightsSHA256:      "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
		TrainingDatasetIDs: []string{"dataset_legal_corpus_v2", "dataset_sec_filings_2026"},
		TrainingCommitSHA:  "1234567890abcdef1234567890abcdef12345678",
		CreatedTimestamp:   time.Now().UTC(),
	}
	_, err = engine.RegisterModel(fineTuned)
	if err != nil {
		t.Fatalf("failed to register fine-tuned model: %v", err)
	}

	// 3. Build Graph
	graph, err := engine.BuildLineageGraph("enterprise/llama3-legal-advisor")
	if err != nil {
		t.Fatalf("BuildLineageGraph failed: %v", err)
	}

	if len(graph.Nodes) != 2 {
		t.Errorf("expected 2 nodes in lineage graph, got %d", len(graph.Nodes))
	}
	if len(graph.Edges) != 1 {
		t.Errorf("expected 1 edge in lineage graph, got %d", len(graph.Edges))
	}
	if graph.GraphHash == "" {
		t.Error("expected non-empty GraphHash")
	}

	tree := RenderProvenanceTree(graph)
	if !strings.Contains(tree, "AIROM MODEL SUPPLY CHAIN PROVENANCE") {
		t.Error("rendered tree missing header banner")
	}
	if !strings.Contains(tree, "Llama-3-8B-Base") {
		t.Error("rendered tree missing base model")
	}
}

func TestProvenance_VerifyModelProvenance_SuccessAndTampering(t *testing.T) {
	engine := NewProvenanceEngine(nil)

	node := ModelProvenanceNode{
		ModelID:          "test/verified-model",
		ModelName:        "Verified Model",
		Version:          "1.0.0",
		WeightsSHA256:    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00",
		License:          "Apache-2.0",
		Quantization:     QuantBF16,
		CreatedTimestamp: time.Now().UTC(),
	}
	_, err := engine.RegisterModel(node)
	if err != nil {
		t.Fatalf("failed to register model: %v", err)
	}

	// 1. Success Verification
	res, err := engine.VerifyModelProvenance("test/verified-model", "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00")
	if err != nil {
		t.Fatalf("VerifyModelProvenance failed: %v", err)
	}
	if !res.Verified {
		t.Errorf("expected model to verify successfully, issues: %v", res.Issues)
	}

	// 2. Weights Tampering Detection
	tamperedRes, err := engine.VerifyModelProvenance("test/verified-model", "TAMPERED_HASH_000000000000000000000000000000000000000000000000000000000")
	if err != nil {
		t.Fatalf("VerifyModelProvenance failed: %v", err)
	}
	if tamperedRes.Verified {
		t.Error("expected verification to fail on tampered weights SHA")
	}
	if tamperedRes.WeightsChecksumValid {
		t.Error("expected WeightsChecksumValid to be false")
	}
}

func TestProvenance_GenerateSLSAStatement(t *testing.T) {
	engine := NewProvenanceEngine(nil)
	node := ModelProvenanceNode{
		ModelID:           "test/slsa-model",
		ModelName:         "SLSA Model",
		WeightsSHA256:     "abc",
		TrainingCommitSHA: "commit123",
	}

	stmt, err := engine.GenerateSLSAStatement(node)
	if err != nil {
		t.Fatalf("GenerateSLSAStatement failed: %v", err)
	}

	if stmt["_type"] != "https://in-toto.io/Statement/v1" {
		t.Errorf("expected in-toto statement type, got %v", stmt["_type"])
	}
}

func TestProvenance_REST_API(t *testing.T) {
	svc := NewService()
	ts := httptest.NewServer(svc.Routes())
	defer ts.Close()

	client := ts.Client()

	// 1. POST /api/v1/provenance/models
	modelPayload := ModelProvenanceNode{
		ModelID:          "api/test-model",
		ModelName:        "API Model",
		Version:          "1.0.0",
		WeightsSHA256:    "aabbccddeeff",
		License:          "MIT",
		Quantization:     QuantFP16,
		CreatedTimestamp: time.Now().UTC(),
	}
	body, _ := json.Marshal(modelPayload)

	resp, err := client.Post(ts.URL+"/api/v1/provenance/models", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("register request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("expected HTTP 201 Created, got %d", resp.StatusCode)
	}

	// 2. GET /api/v1/provenance/graph?model_id=api/test-model
	graphResp, err := client.Get(ts.URL + "/api/v1/provenance/graph?model_id=api/test-model")
	if err != nil {
		t.Fatalf("graph request failed: %v", err)
	}
	defer func() { _ = graphResp.Body.Close() }()

	if graphResp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK for graph, got %d", graphResp.StatusCode)
	}

	// 3. GET /healthz
	hResp, err := client.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz failed: %v", err)
	}
	defer func() { _ = hResp.Body.Close() }()

	if hResp.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP 200 for healthz, got %d", hResp.StatusCode)
	}
}
