// Package stego implements neural steganography detection and hidden payload extraction
// from model weight tensors (ARCHITECTURE.md §16).
package stego

import (
	"time"
)

// StegoMethod classifies the steganographic embedding mechanism.
type StegoMethod string

const (
	MethodLSBQuantized       StegoMethod = "lsb_quantized_bits"   // Least significant bits of quantized weights
	MethodScaleFactorPadding StegoMethod = "scale_factor_padding" // Payload packed in tensor metadata / scale buffers
	MethodSparseZeroEncoding StegoMethod = "sparse_zero_encoding" // Secret binary encoded in sparsity masks
)

// StegoFinding records a decoded payload discovered inside a model's weights.
type StegoFinding struct {
	LayerName     string      `json:"layerName"`
	Method        StegoMethod `json:"method"`
	ExtractedData []byte      `json:"extractedData"`
	PayloadUTF8   string      `json:"payloadUtf8,omitempty"`
	ByteLength    int         `json:"byteLength"`
	EntropyScore  float64     `json:"entropyScore"` // High entropy = encrypted or compressed secret
	SHA256        string      `json:"sha256"`
}

// StegoScanResult summarizes steganography analysis across all model tensors.
type StegoScanResult struct {
	ModelName     string         `json:"modelName"`
	TotalLayers   int            `json:"totalLayers"`
	StegoDetected bool           `json:"stegoDetected"`
	Findings      []StegoFinding `json:"findings"`
	ScannedAt     time.Time      `json:"scannedAt"`
}
