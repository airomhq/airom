package provenance

import (
	"testing"
	"time"
)

func TestQA_AdversarialForgedCosignSignature(t *testing.T) {
	engine := NewProvenanceEngine(nil)

	node := ModelProvenanceNode{
		ModelID:          "test/adversarial-model",
		ModelName:        "Adversarial Model",
		Version:          "1.0.0",
		WeightsSHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		License:          "MIT",
		Quantization:     QuantFP16,
		CreatedTimestamp: time.Now().UTC(),
	}

	reg, err := engine.RegisterModel(node)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Adversarial Attack: Mutate weights SHA directly in registry without regenerating signature
	reg.WeightsSHA256 = "MALICIOUS_POISONED_WEIGHTS_00000000000000000000000000000000000000000"
	engine.models[reg.ModelID] = *reg

	res, err := engine.VerifyModelProvenance("test/adversarial-model", reg.WeightsSHA256)
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if res.Verified {
		t.Fatal("expected verification to fail on forged/tampered model attestation")
	}
	if res.SignatureValid {
		t.Error("expected signature to be invalid after weights hash mutation")
	}
}

func TestQA_AdversarialUnregisteredBaseModel(t *testing.T) {
	engine := NewProvenanceEngine(nil)

	node := ModelProvenanceNode{
		ModelID:          "enterprise/fine-tune",
		ModelName:        "Fine Tune",
		BaseModelID:      "nonexistent/unregistered-foundation-model", // Unregistered base model
		WeightsSHA256:    "11223344",
		CreatedTimestamp: time.Now().UTC(),
	}

	_, _ = engine.RegisterModel(node)

	res, err := engine.VerifyModelProvenance("enterprise/fine-tune", "11223344")
	if err != nil {
		t.Fatalf("verification error: %v", err)
	}
	if res.Verified {
		t.Fatal("expected verification to fail when upstream base model is unregistered")
	}
	if res.LineageChainValid {
		t.Error("expected LineageChainValid to be false")
	}
}

func TestQA_AdversarialCyclicModelLineage(t *testing.T) {
	engine := NewProvenanceEngine(nil)

	// A -> B and B -> A (cyclic dependency)
	modelA := ModelProvenanceNode{
		ModelID:          "model_a",
		ModelName:        "Model A",
		BaseModelID:      "model_b",
		WeightsSHA256:    "sha_a",
		CreatedTimestamp: time.Now().UTC(),
	}
	modelB := ModelProvenanceNode{
		ModelID:          "model_b",
		ModelName:        "Model B",
		BaseModelID:      "model_a",
		WeightsSHA256:    "sha_b",
		CreatedTimestamp: time.Now().UTC(),
	}

	_, _ = engine.RegisterModel(modelA)
	_, _ = engine.RegisterModel(modelB)

	// Must terminate cleanly without infinite loop
	graph, err := engine.BuildLineageGraph("model_a")
	if err != nil {
		t.Fatalf("BuildLineageGraph failed: %v", err)
	}
	if len(graph.Nodes) != 2 {
		t.Errorf("expected 2 nodes in cyclic graph, got %d", len(graph.Nodes))
	}
}
