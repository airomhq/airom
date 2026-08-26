// Package tee verifies hardware Trusted Execution Environment (TEE) attestation quotes
// for AMD SEV-SNP, Intel TDX, NVIDIA H100/H200 CC, and AWS Nitro Enclaves.
package tee

import (
	"time"
)

// Platform identifies the hardware confidential computing environment.
type Platform string

const (
	PlatformAMDSEVSNP Platform = "AMD_SEV_SNP"
	PlatformIntelTDX  Platform = "INTEL_TDX"
	PlatformNVIDIACC  Platform = "NVIDIA_H100_CC"
	PlatformNitro     Platform = "AWS_NITRO_ENCLAVE"
)

// AttestationQuote represents a signed hardware attestation payload.
type AttestationQuote struct {
	Platform          Platform          `json:"platform"`
	EnclaveID         string            `json:"enclaveId"`
	MeasurementHash   string            `json:"measurementHash"`   // Launch digest (e.g. SHA-384/512 of initial enclave memory)
	HostData          string            `json:"hostData"`          // User-supplied nonce / public key commitment
	ChipID            string            `json:"chipId"`            // Unique physical silicon identifier
	PlatformCertChain string            `json:"platformCertChain"` // Root-of-Trust cert (VCEK / PCK)
	TCBVersion        int               `json:"tcbVersion"`        // Trusted Computing Base security level
	SecurityVersion   int               `json:"securityVersion"`
	Registers         map[string]string `json:"registers,omitempty"` // VMR0-VMR3 / PCR0-PCR8 measurements
	SignedAt          time.Time         `json:"signedAt"`
}

// VerificationVerdict models the hardware attestation evaluation.
type VerificationVerdict struct {
	EnclaveID    string    `json:"enclaveId"`
	Platform     Platform  `json:"platform"`
	Valid        bool      `json:"valid"`
	TCBCompliant bool      `json:"tcbCompliant"`
	Violations   []string  `json:"violations"`
	VerifiedAt   time.Time `json:"verifiedAt"`
}
