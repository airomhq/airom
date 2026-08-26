// Package transpiler provides bidirectional lossless conversion between
// CycloneDX 1.6/1.7, SPDX 3.0.1 AI Profile, native AIROM JSON, and OpenVEX.
package transpiler

import (
	"time"
)

// Format defines supported supply chain manifest formats.
type Format string

const (
	FormatCycloneDX  Format = "CYCLONEDX"
	FormatSPDX3      Format = "SPDX3"
	FormatNativeJSON Format = "NATIVE_JSON"
	FormatOpenVEX    Format = "OPENVEX"
)

// TranspileRequest models a manifest translation request.
type TranspileRequest struct {
	SourceFormat Format `json:"sourceFormat"`
	TargetFormat Format `json:"targetFormat"`
	Payload      []byte `json:"payload"`
}

// TranspileResult contains the converted manifest document.
type TranspileResult struct {
	SourceFormat   Format    `json:"sourceFormat"`
	TargetFormat   Format    `json:"targetFormat"`
	OutputPayload  []byte    `json:"outputPayload"`
	ComponentsRead int       `json:"componentsRead"`
	ConvertedAt    time.Time `json:"convertedAt"`
}
