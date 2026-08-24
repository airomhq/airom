package watermark

import (
	"fmt"
	"strings"
	"testing"
)

func TestQA_AdversarialEmptyAndSingleTokenInputs(t *testing.T) {
	cfg := DefaultWatermarkConfig("key")
	detector := NewDetector(cfg)

	// Empty string
	res0 := detector.Detect("")
	if res0.TotalTokens != 0 || res0.IsWatermarked {
		t.Errorf("empty input error: %+v", res0)
	}

	// Single token (no transitions)
	res1 := detector.Detect("single")
	if res1.TotalTokens != 1 || res1.IsWatermarked {
		t.Errorf("single token error: %+v", res1)
	}
}

func TestQA_AdversarialKeySubstitution(t *testing.T) {
	keyA := "enterprise-secret-a"
	keyB := "enterprise-secret-b"

	wmA := NewWatermarker(DefaultWatermarkConfig(keyA))
	detectorB := NewDetector(DefaultWatermarkConfig(keyB))

	// Synthesize text watermarked with Key A
	current := "start"
	var tokens []string
	tokens = append(tokens, current)

	for i := 0; i < 100; i++ {
		candidate := fmt.Sprintf("token_%d", i)
		if wmA.IsGreenlist(current, candidate) {
			current = candidate
			tokens = append(tokens, current)
		}
	}

	textA := strings.Join(tokens, " ")

	// Detector B (with wrong key) should NOT detect a watermark signal
	resB := detectorB.Detect(textA)
	if resB.IsWatermarked {
		t.Errorf("false positive: wrong key detected watermark with z-score %f", resB.ZScore)
	}
}
