package cemark

import (
	"fmt"
	"time"
)

// Generator produces EU Declarations of Conformity and EU Database packages.
type Generator struct{}

// NewGenerator constructs a CE mark and declaration generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// GenerateDeclaration draws up the legal EU Declaration of Conformity under Article 47 & Annex V.
func (g *Generator) GenerateDeclaration(systemName, provider, address, signerName, signerRole, place string) DeclarationOfConformity {
	return DeclarationOfConformity{
		DeclarationID:      fmt.Sprintf("eu-doc-%s-%d", systemName, time.Now().UnixNano()),
		SystemName:         systemName,
		ProviderName:       provider,
		ProviderAddress:    address,
		ConformityStandard: "Annex VI (Conformity assessment based on internal control)",
		StatutoryDirectives: []string{
			"Regulation (EU) 2024/1689 (Artificial Intelligence Act)",
			"Regulation (EU) 2016/679 (General Data Protection Regulation - GDPR)",
		},
		SignerName:    signerName,
		SignerRole:    signerRole,
		PlaceOfIssue:  place,
		DateOfIssue:   time.Now().UTC(),
		CEMarkAffixed: true,
	}
}

// GenerateEUDatabaseEntry creates the Article 71 structured database registration payload.
func (g *Generator) GenerateEUDatabaseEntry(systemName, provider, category, purpose, techDocRef, docRef string) EUDatabaseEntry {
	return EUDatabaseEntry{
		RegistrationID:    fmt.Sprintf("eu-db-%s-%d", systemName, time.Now().UnixNano()),
		SystemName:        systemName,
		ProviderName:      provider,
		AnnexIIICategory:  category,
		IntendedPurpose:   purpose,
		Status:            "PLACED_ON_MARKET",
		TechnicalDocRef:   techDocRef,
		DeclarationDocRef: docRef,
		RegisteredAt:      time.Now().UTC(),
	}
}
