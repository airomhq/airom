package tee

import (
	"testing"
	"time"
)

func TestTEE_AMDSEVSNPValidPasses(t *testing.T) {
	verifier := NewVerifier(15)

	quote := AttestationQuote{
		Platform:          PlatformAMDSEVSNP,
		EnclaveID:         "enclave-model-infer-1",
		MeasurementHash:   "sha384:abcdef1234567890abcdef1234567890",
		HostData:          "0x123456789abcdef",
		ChipID:            "amd-epyc-milan-silicon-99",
		PlatformCertChain: "CERT_CHAIN_VALID_AMD_VCEK",
		TCBVersion:        18,
		SecurityVersion:   2,
		SignedAt:          time.Now().UTC(),
	}

	verdict := verifier.VerifyQuote(quote)
	if !verdict.Valid || !verdict.TCBCompliant || len(verdict.Violations) != 0 {
		t.Fatalf("expected valid AMD SEV-SNP attestation, got violations: %+v", verdict.Violations)
	}
}

func TestTEE_OutdatedTCBFails(t *testing.T) {
	verifier := NewVerifier(20)

	unsafeQuote := AttestationQuote{
		Platform:          PlatformIntelTDX,
		EnclaveID:         "enclave-old-firmware",
		MeasurementHash:   "sha384:abcdef",
		PlatformCertChain: "CERT_REVOKED_BY_MANUFACTURER",
		TCBVersion:        5,                                    // Outdated TCB < 20
		SignedAt:          time.Now().UTC().Add(-2 * time.Hour), // Expired quote
	}

	verdict := verifier.VerifyQuote(unsafeQuote)
	if verdict.Valid || len(verdict.Violations) < 3 {
		t.Fatalf("expected unsafe quote to trigger at least 3 violations, got %d", len(verdict.Violations))
	}
}
