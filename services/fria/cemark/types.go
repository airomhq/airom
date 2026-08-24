// Package cemark implements EU AI Act Declaration of Conformity, CE marking,
// and EU Database registration pursuant to Articles 47, 48, 71, and Annexes V, VIII (ARCHITECTURE.md §16).
package cemark

import (
	"time"
)

// DeclarationOfConformity contains the legal document mandated under Article 47 and Annex V.
type DeclarationOfConformity struct {
	DeclarationID       string    `json:"declarationId"`
	SystemName          string    `json:"systemName"`
	ProviderName        string    `json:"providerName"`
	ProviderAddress     string    `json:"providerAddress"`
	AuthorizedRep       string    `json:"authorizedRepresentative,omitempty"`
	ConformityStandard  string    `json:"conformityStandard"` // "Annex VI (Internal Control)" or "Annex VII (Notified Body)"
	NotifiedBodyID      string    `json:"notifiedBodyId,omitempty"`
	StatutoryDirectives []string  `json:"statutoryDirectives"`
	SignerName          string    `json:"signerName"`
	SignerRole          string    `json:"signerRole"`
	PlaceOfIssue        string    `json:"placeOfIssue"`
	DateOfIssue         time.Time `json:"dateOfIssue"`
	CEMarkAffixed       bool      `json:"ceMarkAffixed"`
}

// EUDatabaseEntry contains the structured registration payload for the Article 71 EU High-Risk AI Database.
type EUDatabaseEntry struct {
	RegistrationID    string    `json:"registrationId"`
	SystemName        string    `json:"systemName"`
	ProviderName      string    `json:"providerName"`
	AnnexIIICategory  string    `json:"annexIiiCategory"`
	IntendedPurpose   string    `json:"intendedPurpose"`
	Status            string    `json:"status"` // "PLACED_ON_MARKET" | "IN_SERVICE"
	TechnicalDocRef   string    `json:"technicalDocRef"`
	DeclarationDocRef string    `json:"declarationDocRef"`
	RegisteredAt      time.Time `json:"registeredAt"`
}
