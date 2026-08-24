// Package bundle implements offline cryptographic air-gap bundle compilation and verification
// for disconnected SCIF and sovereign government enterprise environments (ARCHITECTURE.md §16).
package bundle

import (
	"time"
)

// Manifest contains cryptographic metadata for an air-gapped offline package.
type Manifest struct {
	BundleID        string    `json:"bundleId"`
	Version         string    `json:"version"`
	CompiledAt      time.Time `json:"compiledAt"`
	RulePackCount   int       `json:"rulePackCount"`
	WasmParserCount int       `json:"wasmParserCount"`
	VulnDBEntries   int       `json:"vulnDbEntries"`
	ContentSHA256   string    `json:"contentSha256"`
	CosignSignature string    `json:"cosignSignature"`
	AirGapCertified bool      `json:"airGapCertified"`
}

// AirGapPackage represents an in-memory or persisted cryptographic offline bundle.
type AirGapPackage struct {
	Manifest Manifest          `json:"manifest"`
	Payloads map[string][]byte `json:"payloads"` // File path -> raw bytes
}
