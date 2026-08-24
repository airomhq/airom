package watermark

import (
	"fmt"
	"strings"
	"testing"
)

func TestWatermark_GreenlistSelection(t *testing.T) {
	cfg := DefaultWatermarkConfig("secret-enterprise-key")
	wm := NewWatermarker(cfg)

	// Deterministic result
	r1 := wm.IsGreenlist("the", "model")
	r2 := wm.IsGreenlist("the", "model")
	if r1 != r2 {
		t.Errorf("expected deterministic greenlist result")
	}
}

func TestWatermark_StatisticalDetection(t *testing.T) {
	cfg := DefaultWatermarkConfig("secret-enterprise-key")
	wm := NewWatermarker(cfg)
	detector := NewDetector(cfg)

	// Synthetic watermarked text: pick greenlist continuation for 200 tokens
	vocab := []string{"apple", "banana", "cherry", "date", "elderberry", "fig", "grape", "honeydew"}
	current := "start"
	var watermarkedTokens []string
	watermarkedTokens = append(watermarkedTokens, current)

	for i := 0; i < 200; i++ {
		for _, next := range vocab {
			candidate := fmt.Sprintf("%s_%d", next, i)
			if wm.IsGreenlist(current, candidate) {
				current = candidate
				watermarkedTokens = append(watermarkedTokens, current)
				break
			}
		}
	}

	watermarkedText := strings.Join(watermarkedTokens, " ")
	res := detector.Detect(watermarkedText)

	if !res.IsWatermarked {
		t.Errorf("expected watermarked text detected, z-score: %f, green count: %d/%d", res.ZScore, res.GreenlistCount, res.TotalTokens-1)
	}

	if res.ZScore < 4.0 {
		t.Errorf("expected high z-score >= 4.0, got %f", res.ZScore)
	}

	if res.PValue > 0.001 {
		t.Errorf("expected highly significant p-value, got %f", res.PValue)
	}
}
