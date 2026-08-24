package watermark

import (
	"math"
	"time"
)

// Detector verifies statistical presence of watermark signals in text.
type Detector struct {
	watermarker *Watermarker
	cfg         WatermarkConfig
}

// NewDetector constructs a statistical watermark detector.
func NewDetector(cfg WatermarkConfig) *Detector {
	return &Detector{
		watermarker: NewWatermarker(cfg),
		cfg:         cfg,
	}
}

// Detect computes the z-score of greenlist token frequency in input text.
func (d *Detector) Detect(text string) VerificationResult {
	tokens := Tokenize(text)
	N := len(tokens) - 1 // Transitions

	if N <= 0 {
		return VerificationResult{
			TotalTokens: len(tokens),
			VerifiedAt:  time.Now().UTC(),
		}
	}

	greenCount := 0
	for i := 1; i < len(tokens); i++ {
		prev := tokens[i-1]
		curr := tokens[i]
		if d.watermarker.IsGreenlist(prev, curr) {
			greenCount++
		}
	}

	gamma := d.cfg.Gamma
	expectedGreen := float64(N) * gamma
	variance := float64(N) * gamma * (1.0 - gamma)
	stdDev := math.Sqrt(variance)

	zScore := 0.0
	if stdDev > 0 {
		zScore = (float64(greenCount) - expectedGreen) / stdDev
	}

	// Normal cumulative distribution approximation for one-tailed p-value
	pValue := 0.5 * math.Erfc(zScore/math.Sqrt2)

	isWatermarked := zScore >= 4.0 || (N >= 50 && zScore >= 3.0)
	confidence := math.Min(1.0, math.Max(0.0, 1.0-pValue))

	return VerificationResult{
		TotalTokens:    len(tokens),
		GreenlistCount: greenCount,
		ExpectedGreen:  expectedGreen,
		ZScore:         zScore,
		PValue:         pValue,
		IsWatermarked:  isWatermarked,
		Confidence:     confidence,
		VerifiedAt:     time.Now().UTC(),
	}
}
