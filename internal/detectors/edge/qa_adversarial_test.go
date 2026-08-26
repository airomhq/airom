package edge

import (
	"testing"
)

func TestQA_AdversarialNegativeMemoryAllocations(t *testing.T) {
	verifier := NewVerifier()

	negativeBinding := EdgeModelBinding{
		ModelName: "neg_alloc.engine",
		Platform:  PlatformTensorRT,
		MemorySpec: MemoryBoundarySpec{
			MaxSRAMUsageBytes:       -1024,
			DeterministicDeadlineMs: -50,
		},
	}

	res := verifier.VerifyModel(negativeBinding)
	if res.IsSafe {
		t.Fatalf("expected negative allocation and deadline to fail verification")
	}
}

func TestQA_AdversarialUnknownPlatform(t *testing.T) {
	verifier := NewVerifier()

	customBinding := EdgeModelBinding{
		ModelName:          "custom.bin",
		Platform:           TargetPlatform("CUSTOM_ASIC_CHIP"),
		HasRingBufferGuard: true,
		MemorySpec: MemoryBoundarySpec{
			MaxSRAMUsageBytes:       1024,
			ZeroCopyVerified:        true,
			DeterministicDeadlineMs: 10,
		},
	}

	res := verifier.VerifyModel(customBinding)
	if !res.IsSafe {
		t.Fatalf("expected valid verification for custom ASIC chip")
	}
}
