// Package proto provides protobuf/gRPC message structures for AIROM out-of-process plugins.
package proto

import (
	"github.com/airomhq/airom/pkg/airom"
)

// DetectRequest carries a single source file to a custom detector plugin.
type DetectRequest struct {
	SessionID string            `json:"sessionId"`
	FilePath  string            `json:"filePath"`
	Content   []byte            `json:"content"`
	Language  string            `json:"language"`
	Config    map[string]string `json:"config,omitempty"`
}

// DetectResponse returns discovered components and relationships.
type DetectResponse struct {
	Components    []airom.Component    `json:"components,omitempty"`
	Relationships []airom.Relationship `json:"relationships,omitempty"`
	Error         string               `json:"error,omitempty"`
}

// WriteRequest asks a custom writer plugin to serialize an inventory.
type WriteRequest struct {
	SessionID string           `json:"sessionId"`
	Format    string           `json:"format"`
	Inventory *airom.Inventory `json:"inventory"`
	Options   map[string]any   `json:"options,omitempty"`
}

// WriteResponse returns formatted bytes.
type WriteResponse struct {
	Output []byte `json:"output"`
	Error  string `json:"error,omitempty"`
}

// AuditRequest passes compliance assessment data to a custom auditor plugin.
type AuditRequest struct {
	SessionID    string           `json:"sessionId"`
	Jurisdiction string           `json:"jurisdiction"`
	Inventory    *airom.Inventory `json:"inventory"`
	PolicyID     string           `json:"policyId"`
}

// AuditResponse returns verification results and custom compliance verdicts.
type AuditResponse struct {
	Passed          bool     `json:"passed"`
	StatutoryGaps   []string `json:"statutoryGaps,omitempty"`
	AttestationHash string   `json:"attestationHash,omitempty"`
	Error           string   `json:"error,omitempty"`
}
