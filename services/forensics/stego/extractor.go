package stego

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"unicode/utf8"
)

// Extractor decodes and evaluates neural steganography in weight matrices.
type Extractor struct{}

// NewExtractor constructs a neural stego extractor.
func NewExtractor() *Extractor {
	return &Extractor{}
}

// ExtractLSBBytes extracts bytes from the least significant bit of quantized uint8 / int8 weight arrays.
func (e *Extractor) ExtractLSBBytes(layerName string, quantizedBytes []byte) (StegoFinding, bool) {
	if len(quantizedBytes) < 64 {
		return StegoFinding{}, false
	}

	// Reconstruct bytes by packing 8 consecutive LSBs into one byte
	numDecodedBytes := len(quantizedBytes) / 8
	decoded := make([]byte, numDecodedBytes)

	for i := 0; i < numDecodedBytes; i++ {
		var b byte
		for bit := 0; bit < 8; bit++ {
			lsb := quantizedBytes[i*8+bit] & 1
			b |= (lsb << (7 - bit))
		}
		decoded[i] = b
	}

	entropy := calculateShannonEntropy(decoded)

	// Check if extracted bytes form valid UTF-8 text (e.g. secret keys or commands)
	isPrintable := isMostlyPrintable(decoded)
	hasMagicHeader := len(decoded) >= 4 && (string(decoded[:4]) == "MZ\x90\x00" || string(decoded[:4]) == "\x7fELF" || string(decoded[:4]) == "PK\x03\x04")

	if isPrintable || hasMagicHeader || entropy > 7.5 { // 7.5+ bits/byte indicates encrypted/compressed payload
		h := sha256.Sum256(decoded)
		finding := StegoFinding{
			LayerName:     layerName,
			Method:        MethodLSBQuantized,
			ExtractedData: decoded,
			ByteLength:    len(decoded),
			EntropyScore:  entropy,
			SHA256:        hex.EncodeToString(h[:]),
		}
		if isPrintable && utf8.Valid(decoded) {
			finding.PayloadUTF8 = string(decoded)
		}
		return finding, true
	}

	return StegoFinding{}, false
}

// EmbedLSBBytes embeds a secret payload into quantized weights for testing / simulation.
func EmbedLSBBytes(secret []byte, carrierWeights []byte) []byte {
	modified := make([]byte, len(carrierWeights))
	copy(modified, carrierWeights)

	for i, b := range secret {
		for bit := 0; bit < 8; bit++ {
			idx := i*8 + bit
			if idx < len(modified) {
				bitVal := (b >> (7 - bit)) & 1
				modified[idx] = (modified[idx] & 0xFE) | bitVal
			}
		}
	}

	return modified
}

func calculateShannonEntropy(data []byte) float64 {
	if len(data) == 0 {
		return 0.0
	}

	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}

	var entropy float64
	total := float64(len(data))

	for _, count := range counts {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}

	return entropy
}

func isMostlyPrintable(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printableCount := 0
	for _, b := range data {
		if (b >= 32 && b <= 126) || b == '\n' || b == '\r' || b == '\t' {
			printableCount++
		}
	}
	return float64(printableCount)/float64(len(data)) > 0.85
}
