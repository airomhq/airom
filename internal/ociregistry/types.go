// Package ociregistry implements OCI distribution artifact packaging and registry sync
// for AIROM rule packs (ARCHITECTURE.md §10, §16).
package ociregistry

import (
	"time"
)

const (
	// MediaTypeRulePackLayer is the OCI layer media type for an AIROM rule bundle.
	MediaTypeRulePackLayer = "application/vnd.airom.rulepack.v1.tar+gzip"
	// MediaTypeRulePackConfig is the OCI config media type.
	MediaTypeRulePackConfig = "application/vnd.airom.config.v1+json"
	// MediaTypeOCIManifest is the standard OCI image manifest media type.
	MediaTypeOCIManifest = "application/vnd.oci.image.manifest.v1+json"
)

// RuleBundleMeta describes a packaged set of AI compliance rules.
type RuleBundleMeta struct {
	Name        string    `json:"name"`
	Version     string    `json:"version"`
	Description string    `json:"description,omitempty"`
	Author      string    `json:"author,omitempty"`
	CreatedAt   time.Time `json:"createdAt"`
	RuleCount   int       `json:"ruleCount"`
	TotalBytes  int64     `json:"totalBytes"`
	Digest      string    `json:"digest"` // SHA-256
}

// RegistryConfig configures credentials and endpoints for OCI registry communication.
type RegistryConfig struct {
	RegistryHost string        `json:"registryHost"` // ghcr.io, ecr.aws, etc.
	Username     string        `json:"username,omitempty"`
	Password     string        `json:"password,omitempty"`
	Token        string        `json:"token,omitempty"`
	Insecure     bool          `json:"insecure,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty"`
}

// OCIDescriptor represents an OCI Content Descriptor.
type OCIDescriptor struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// OCIManifest represents an OCI Image Manifest for an AIROM rule pack.
type OCIManifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        OCIDescriptor     `json:"config"`
	Layers        []OCIDescriptor   `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}
