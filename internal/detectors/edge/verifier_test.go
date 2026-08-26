package edge

import (
	"testing"
)

func TestEdge_CompliantTensorRTPasses(t *testing.T) {
	verifier := NewVerifier()

	binding := EdgeModelBinding{
		ModelName:          "perception_backbone.engine",
		Platform:           PlatformTensorRT,
		Quantization:       "INT8_PTQ",
		HasRingBufferGuard: true,
		MemorySpec: MemoryBoundarySpec{
			MaxSRAMUsageBytes:       8 * 1024 * 1024, // 8MB
			SharedDMABoundaryBytes:  64 * 1024 * 1024,
			ZeroCopyVerified:        true,
			DeterministicDeadlineMs: 15,
		},
	}

	res := verifier.VerifyModel(binding)
	if !res.IsSafe || len(res.Violations) != 0 {
		t.Fatalf("expected safe edge model, got violations: %+v", res.Violations)
	}

	if res.Component == nil || res.Component.Name != "perception_backbone.engine" {
		t.Errorf("unexpected component: %+v", res.Component)
	}
}

func TestEdge_SRAMOverflowFails(t *testing.T) {
	verifier := NewVerifier()

	unsafeBinding := EdgeModelBinding{
		ModelName:          "giant_unquantized.onnx",
		Platform:           PlatformQualcommNPU,
		Quantization:       "FP32",
		HasRingBufferGuard: false,
		MemorySpec: MemoryBoundarySpec{
			MaxSRAMUsageBytes:       128 * 1024 * 1024, // 128MB (exceeds 32MB NPU limit)
			DeterministicDeadlineMs: 200,               // Exceeds 50ms deadline
		},
	}

	res := verifier.VerifyModel(unsafeBinding)
	if res.IsSafe || len(res.Violations) < 3 {
		t.Fatalf("expected unsafe edge model to trigger at least 3 violations, got %d", len(res.Violations))
	}
}
