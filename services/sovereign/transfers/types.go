// Package transfers implements cross-border AI data and model weight transfer compliance
// pursuant to GDPR Chapter V, EU-US DPF, and China CAC Security Assessment (ARCHITECTURE.md §16).
package transfers

import (
	"time"
)

// Jurisdiction identifies a regulatory sovereign zone.
type Jurisdiction string

const (
	JurisdictionEU_EEA     Jurisdiction = "EU_EEA"
	JurisdictionUS         Jurisdiction = "US"
	JurisdictionUK         Jurisdiction = "UK"
	JurisdictionChina      Jurisdiction = "China"
	JurisdictionJapan      Jurisdiction = "Japan"
	JurisdictionSingapore  Jurisdiction = "Singapore"
	JurisdictionSanctioned Jurisdiction = "Sanctioned_Embargoed"
)

// LegalTransferMechanism defines the valid statutory instrument authorizing cross-border movement.
type LegalTransferMechanism string

const (
	MechanismAdequacyDecision LegalTransferMechanism = "eu_adequacy_decision"
	MechanismEU_US_DPF        LegalTransferMechanism = "eu_us_data_privacy_framework"
	MechanismStandardClauses  LegalTransferMechanism = "eu_standard_contractual_clauses_scc"
	MechanismChinaCACApproval LegalTransferMechanism = "china_cac_security_assessment"
	MechanismNone             LegalTransferMechanism = "none_unauthorized"
)

// TransferRequest represents a planned replication or API stream across sovereign borders.
type TransferRequest struct {
	TransferID       string                 `json:"transferId"`
	Origin           Jurisdiction           `json:"origin"`
	Destination      Jurisdiction           `json:"destination"`
	DataPayloadType  string                 `json:"dataPayloadType"` // "model_weights" | "training_dataset" | "prompt_inference_stream"
	ContainsPII      bool                   `json:"containsPii"`
	MechanismClaimed LegalTransferMechanism `json:"mechanismClaimed"`
}

// TransferDecision records whether the cross-border movement is approved or blocked.
type TransferDecision struct {
	TransferID       string    `json:"transferId"`
	Approved         bool      `json:"approved"`
	StatutoryBasis   string    `json:"statutoryBasis"`
	MandatoryActions []string  `json:"mandatoryActions"`
	EvaluatedAt      time.Time `json:"evaluatedAt"`
}
