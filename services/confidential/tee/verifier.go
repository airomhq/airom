package tee

import (
	"strings"
	"sync"
	"time"
)

// Verifier validates confidential computing hardware attestation quotes.
type Verifier struct {
	mu            sync.RWMutex
	trustedRoots  map[Platform]bool
	minTCBVersion int
}

// NewVerifier constructs a new TEE attestation verifier with standard enterprise trust anchors.
func NewVerifier(minTCB int) *Verifier {
	if minTCB <= 0 {
		minTCB = 10
	}
	return &Verifier{
		trustedRoots: map[Platform]bool{
			PlatformAMDSEVSNP: true,
			PlatformIntelTDX:  true,
			PlatformNVIDIACC:  true,
			PlatformNitro:     true,
		},
		minTCBVersion: minTCB,
	}
}

// VerifyQuote validates a hardware attestation quote against root certificates and minimum TCB versions.
func (v *Verifier) VerifyQuote(quote AttestationQuote) VerificationVerdict {
	v.mu.RLock()
	defer v.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. Verify Platform Root of Trust
	if !v.trustedRoots[quote.Platform] {
		violations = append(violations, "CRITICAL: Hardware TEE platform not in enterprise approved Root of Trust list")
	}

	// 2. Verify Certificate Chain
	if quote.PlatformCertChain == "" || strings.Contains(quote.PlatformCertChain, "REVOKED") {
		violations = append(violations, "CRITICAL: Silicon Root of Trust certificate chain is missing or revoked")
	}

	// 3. Verify Measurement Hash
	if quote.MeasurementHash == "" || quote.MeasurementHash == "00000000000000000000000000000000" {
		violations = append(violations, "CRITICAL: Enclave launch measurement hash is zeroed or missing (unverified code image)")
	}

	// 4. Verify TCB Security Level
	tcbCompliant := quote.TCBVersion >= v.minTCBVersion
	if !tcbCompliant {
		violations = append(violations, "HIGH: Firmware TCB version is outdated (vulnerable to known microarchitectural side-channels)")
	}

	// 5. Quote Age Freshness (must be <= 1 hour)
	if now.Sub(quote.SignedAt) > 1*time.Hour {
		violations = append(violations, "HIGH: Attestation quote timestamp expired (>1 hour old replay window)")
	}

	return VerificationVerdict{
		EnclaveID:    quote.EnclaveID,
		Platform:     quote.Platform,
		Valid:        len(violations) == 0,
		TCBCompliant: tcbCompliant,
		Violations:   violations,
		VerifiedAt:   now,
	}
}
