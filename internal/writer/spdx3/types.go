// Package spdx3 defines the formal SPDX 3.0.1 domain metamodel and JSON-LD serializer
// for the AI, Dataset, Software, and Security profiles (ARCHITECTURE.md §11).
package spdx3

import (
	"encoding/json"
	"time"
)

const (
	// ContextIRI is the canonical JSON-LD context for SPDX 3.0.1.
	ContextIRI = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
	// SpecVersion is the SPDX 3.0.1 specification version string.
	SpecVersion = "3.0.1"

	// NoAssertion is the standard sentinel for unknown or unasserted values.
	NoAssertion = "NOASSERTION"
	// NoAssertionElement is the canonical IRI for an unasserted element reference.
	NoAssertionElement = "https://spdx.org/rdf/3.0.1/terms/Core/NoAssertionElement"
)

// Document is the root SPDX 3.0.1 JSON-LD container.
type Document struct {
	Context string    `json:"@context"`
	Graph   []Element `json:"@graph"`
}

// Element is the universal base interface for all SPDX 3.0.1 elements.
type Element interface {
	GetSpdxID() string
	GetType() string
}

// BaseElement carries common fields shared across all SPDX 3.0.1 elements.
type BaseElement struct {
	Type               string               `json:"@type"`
	SpdxID             string               `json:"@id"`
	CreationInfo       *CreationInfo        `json:"creationInfo,omitempty"`
	Name               string               `json:"name,omitempty"`
	Summary            string               `json:"summary,omitempty"`
	Description        string               `json:"description,omitempty"`
	Comment            string               `json:"comment,omitempty"`
	VerifiedUsing      []IntegrityMethod    `json:"verifiedUsing,omitempty"`
	ExternalRef        []ExternalRef        `json:"externalRef,omitempty"`
	ExternalIdentifier []ExternalIdentifier `json:"externalIdentifier,omitempty"`
	Extension          []Extension          `json:"extension,omitempty"`
}

// GetSpdxID returns the element's @id.
func (b *BaseElement) GetSpdxID() string { return b.SpdxID }

// GetType returns the element's @type.
func (b *BaseElement) GetType() string { return b.Type }

// CreationInfo records who, when, and with what tool an element was created.
type CreationInfo struct {
	SpecVersion  string    `json:"specVersion"`
	Created      time.Time `json:"created"`
	CreatedBy    []string  `json:"createdBy"`
	CreatedUsing []string  `json:"createdUsing,omitempty"`
	Comment      string    `json:"comment,omitempty"`
}

// IntegrityMethod represents a hash or cryptographic signature verifying an element.
type IntegrityMethod struct {
	Type      string `json:"@type"` // Hash | Signature
	Algorithm string `json:"algorithm,omitempty"`
	HashValue string `json:"hashValue,omitempty"`
	Comment   string `json:"comment,omitempty"`
}

// ExternalRef points to a related resource outside the SPDX document.
type ExternalRef struct {
	Type            string   `json:"@type"`
	ExternalRefType string   `json:"externalRefType"`
	Locator         []string `json:"locator"`
	Comment         string   `json:"comment,omitempty"`
}

// ExternalIdentifier records standard identifiers like purl, cpe23, or gitoid.
type ExternalIdentifier struct {
	Type                   string `json:"@type"`                  // ExternalIdentifier
	ExternalIdentifierType string `json:"externalIdentifierType"` // purl | cpe23Type | gitoid | swhid
	Identifier             string `json:"identifier"`
	Comment                string `json:"comment,omitempty"`
}

// Extension allows arbitrary structured metadata to attach to any element.
type Extension struct {
	Type  string `json:"@type"`
	Key   string `json:"key"`
	Value any    `json:"value"`
}

// SpdxDocumentElement represents the top-level document element in the graph.
type SpdxDocumentElement struct {
	BaseElement
	RootElement []string `json:"rootElement,omitempty"`
	DataLicense string   `json:"dataLicense,omitempty"` // CC0-1.0
}

// Package represents a software package, library, or framework in SPDX 3.
type Package struct {
	BaseElement
	PackageVersion   string `json:"packageVersion,omitempty"`
	DownloadLocation string `json:"downloadLocation,omitempty"`
	PackageURL       string `json:"packageUrl,omitempty"`
	Homepage         string `json:"homepage,omitempty"`
	ConcludedLicense string `json:"concludedLicense,omitempty"`
	DeclaredLicense  string `json:"declaredLicense,omitempty"`
	CopyrightText    string `json:"copyrightText,omitempty"`
	PrimaryPurpose   string `json:"primaryPurpose,omitempty"` // application | framework | library | container | other
	OriginatedBy     string `json:"originatedBy,omitempty"`
	SuppliedBy       string `json:"suppliedBy,omitempty"`
}

// File represents an individual source or artifact file.
type File struct {
	BaseElement
	ContentType      string `json:"contentType,omitempty"`
	ConcludedLicense string `json:"concludedLicense,omitempty"`
	CopyrightText    string `json:"copyrightText,omitempty"`
}

// RelationshipType defines typed relationships in SPDX 3.0.1.
type RelationshipType string

const (
	RelDependsOn     RelationshipType = "dependsOn"
	RelContains      RelationshipType = "contains"
	RelDescribes     RelationshipType = "describes"
	RelTrainedOn     RelationshipType = "trainedOn"
	RelDerivedFrom   RelationshipType = "derivedFrom"
	RelConfiguredBy  RelationshipType = "configuredBy"
	RelTestedOn      RelationshipType = "testedOn"
	RelGenerates     RelationshipType = "generates"
	RelDelegatesTo   RelationshipType = "delegatesTo"
	RelAncestorOf    RelationshipType = "ancestorOf"
	RelVariantOf     RelationshipType = "variantOf"
	RelHasAssessment RelationshipType = "hasAssessment"
	RelOther         RelationshipType = "other"
)

// Relationship connects a source element to one or more target elements.
type Relationship struct {
	BaseElement
	From             string           `json:"from"`
	To               []string         `json:"to"`
	RelationshipType RelationshipType `json:"relationshipType"`
	Completeness     string           `json:"completeness,omitempty"` // known | incomplete | noAssertion
}

// Agent represents an individual, organization, or software tool creating an element.
type Agent struct {
	BaseElement
	AgentType string `json:"agentType"` // Person | Organization | Software
}

// SoftwareAgent represents an automated tool actor (e.g. AIROM).
type SoftwareAgent struct {
	Agent
	SoftwareVersion string `json:"softwareVersion,omitempty"`
}

// MarshalJSON ensures custom JSON serialization for polymorphic elements in the graph.
func (d *Document) MarshalJSON() ([]byte, error) {
	type Alias Document
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(d),
	})
}
