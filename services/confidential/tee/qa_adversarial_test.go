package tee

import (
	"testing"
	"time"
)

func TestQA_AdversarialForgedSiliconChipID(t *testing.T) {
	verifier := NewVerifier(10)

	zeroQuote := AttestationQuote{
		Platform:          PlatformAMDSEVSNP,
		MeasurementHash:   "00000000000000000000000000000000",
		PlatformCertChain: "VALID_CERT",
		TCBVersion:        15,
		SignedAt:          time.Now().UTC(),
	}

	verdict := verifier.VerifyQuote(zeroQuote)
	if verdict.Valid {
		t.Fatalf("SECURITY VIOLATION: zeroed measurement hash validated")
	}
}

func TestQA_AdversarialUnknownPlatformRejection(t *testing.T) {
	verifier := NewVerifier(10)

	fakePlatformQuote := AttestationQuote{
		Platform:          Platform("UNTRUSTED_EMULATOR_QEMU"),
		MeasurementHash:   "sha384:valid",
		PlatformCertChain: "VALID_CERT",
		TCBVersion:        15,
		SignedAt:          time.Now().UTC(),
	}

	verdict := verifier.VerifyQuote(fakePlatformQuote)
	if verdict.Valid {
		t.Fatalf("SECURITY VIOLATION: untrusted emulator platform validated as true TEE")
	}
}
