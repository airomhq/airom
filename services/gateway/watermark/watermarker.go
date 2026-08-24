package watermark

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// Watermarker handles token-level greenlist partitioning.
type Watermarker struct {
	cfg WatermarkConfig
}

// NewWatermarker constructs a token watermarker.
func NewWatermarker(cfg WatermarkConfig) *Watermarker {
	if cfg.Gamma <= 0 || cfg.Gamma >= 1.0 {
		cfg.Gamma = 0.5
	}
	return &Watermarker{cfg: cfg}
}

// IsGreenlist determines whether a token is in the cryptographic greenlist given preceding context.
func (w *Watermarker) IsGreenlist(prevToken, currentToken string) bool {
	mac := hmac.New(sha256.New, []byte(w.cfg.SecretKey))
	mac.Write([]byte(prevToken))
	mac.Write([]byte(":"))
	mac.Write([]byte(currentToken))
	hashBytes := mac.Sum(nil)

	val := binary.BigEndian.Uint32(hashBytes[:4])
	ratio := float64(val) / float64(^uint32(0))

	return ratio < w.cfg.Gamma
}

// Tokenize helper splitting text on whitespace/punctuation.
func Tokenize(text string) []string {
	return strings.Fields(text)
}
