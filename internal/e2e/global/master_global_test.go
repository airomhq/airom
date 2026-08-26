package global

import (
	"testing"

	"github.com/airomhq/airom/internal/detectors/serving"
	"github.com/airomhq/airom/internal/detectors/structured"
	"github.com/airomhq/airom/internal/detectors/vlm"
	"github.com/airomhq/airom/internal/pqc/signatures"
	"github.com/airomhq/airom/services/cicd"
	"github.com/airomhq/airom/services/cockpit"
	"github.com/airomhq/airom/services/hub/huggingface"
	"github.com/airomhq/airom/services/hub/ollama"
	"github.com/airomhq/airom/services/hub/serverless"
	"github.com/airomhq/airom/services/transpiler"
)

func TestMaster_GlobalAIGovernancePlatform_EndToEnd(t *testing.T) {
	// ── 1. HIGH-THROUGHPUT SERVING, STRUCTURED OUTPUTS & VLMS (Sprints 106, 107, 108) ──
	servingDetector := serving.NewDetector()
	serveRes := servingDetector.EvaluateConfig(serving.ServingConfigSpec{
		EngineType:         serving.EngineVLLM,
		ModelName:          "meta-llama/Meta-Llama-3.1-70B-Instruct",
		TensorParallelSize: 4,
		GPUMemoryUtil:      0.90,
		MaxModelLen:        32768,
		KVQuantization:     "fp8",
	})
	if !serveRes.IsConformant {
		t.Fatalf("vLLM serving evaluation failed: %+v", serveRes.Violations)
	}

	structDetector := structured.NewDetector()
	structRes := structDetector.EvaluateCall(structured.StructuredCallSpec{
		EngineType:        structured.EngineInstructor,
		SchemaName:        "CorporateAuditSchema",
		HasTypeValidation: true,
		MaxRetries:        3,
	})
	if !structRes.IsGuaranteed {
		t.Fatalf("structured output evaluation failed: %+v", structRes.Violations)
	}

	vlmDetector := vlm.NewDetector()
	vlmRes := vlmDetector.EvaluateInference(vlm.InferenceSpec{
		Framework:      vlm.FrameworkPixtral,
		ModelID:        "mistralai/Pixtral-12B-2409",
		MaxImagePixels: 4 * 1024 * 1024,
		HasPromptGuard: true,
	})
	if !vlmRes.IsSafe {
		t.Fatalf("Pixtral VLM evaluation failed: %+v", vlmRes.Violations)
	}

	// ── 2. REMOTE MODEL HUBS & SERVERLESS INGESTION (Sprints 109, 110, 111) ──
	hfConnector := huggingface.NewConnector()
	hfRes := hfConnector.CompileAIBOM(huggingface.HFModelCardSpec{
		RepoID:         "meta-llama/Meta-Llama-3.1-8B-Instruct",
		ModelName:      "Meta-Llama-3.1-8B-Instruct",
		License:        "llama3.1",
		GGUFVariants:   []string{"Q4_K_M"},
		ParameterCount: "8B",
	})
	if len(hfRes.Inventory.Components) != 2 {
		t.Fatalf("HuggingFace AIBOM compilation failed")
	}

	ollamaSyncer := ollama.NewSyncer()
	olRes := ollamaSyncer.CompileAIBOM("http://localhost:11434", []ollamaModelSpec{
		{Name: "llama3.1:8b", QuantizationLevel: "Q4_0"},
	})
	if olRes.TotalModels != 1 {
		t.Fatalf("Ollama local synchronization failed")
	}

	serverlessIngestor := serverless.NewIngestor()
	slRes := serverlessIngestor.CompileAIBOM([]serverless.EndpointSpec{
		{Provider: serverless.ProviderGroq, ModelName: "llama-3.3-70b-versatile", HardwareEngine: "LPU"},
	})
	if slRes.TotalEndpoints != 1 {
		t.Fatalf("serverless endpoint ingestion failed")
	}

	// ── 3. COCKPIT, TRANSPILER & CI/CD WORKFLOW COMPILER (Sprints 112, 113, 114) ──
	cockpitServer := cockpit.NewServer(cockpit.CockpitConfig{Organization: "Global Sovereign AI"})
	cockpitServer.PushEvent(cockpit.CockpitEvent{EventID: "evt-master", Type: "GATE_VERIFIED"})

	transpilerEngine := transpiler.NewEngine()
	transRes, err := transpilerEngine.Transpile(transpiler.TranspileRequest{
		SourceFormat: transpiler.FormatCycloneDX,
		TargetFormat: transpiler.FormatSPDX3,
		Payload:      []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"name":"global_model"}]}`),
	})
	if err != nil || transRes.ComponentsRead != 1 {
		t.Fatalf("AIBOM transpilation failed: %v", err)
	}

	cicdCompiler := cicd.NewCompiler()
	ciRes := cicdCompiler.Compile(cicd.PipelineSpec{
		Platform:     cicd.PlatformGitHubActions,
		Framework:    "eu-ai-act",
		FailOnGaps:   true,
		GeneratePDF:  true,
		TargetBranch: "main",
	})
	if len(ciRes.Content) == 0 {
		t.Fatalf("CI/CD pipeline compilation failed")
	}

	// ── 4. POST-QUANTUM CRYPTOGRAPHIC SIGNATURE ENGINE (Sprints 94, 105) ──
	pqcEngine := signatures.NewEngine()
	pqcKey, err := pqcEngine.GenerateKeyPair(signatures.SchemeMLDSA87)
	if err != nil || pqcKey == nil {
		t.Fatalf("PQC key generation failed: %v", err)
	}
	modelDigest := "sha3-512:1234567890abcdef1234567890abcdef1234567890abcdef"
	pqcSig, err := pqcEngine.SignModel(pqcKey, modelDigest)
	if err != nil || pqcSig == nil {
		t.Fatalf("PQC model signing failed: %v", err)
	}
	verdict := pqcEngine.VerifySignature(pqcKey, pqcSig, modelDigest)
	if !verdict.Valid {
		t.Fatalf("PQC signature verification failed: %s", verdict.Reason)
	}
}

type ollamaModelSpec = ollama.OllamaModelSpec
