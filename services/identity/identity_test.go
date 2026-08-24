package identity

import (
	"testing"
	"time"
)

func TestIdentity_IssueAndVerifySVID(t *testing.T) {
	attestor := NewAttestor("airom.internal", "secret-signing-key")

	agentID := AgentIdentity{
		SPIFFEID:    attestor.FormatSPIFFEID("production", "financial-summarizer"),
		TrustDomain: "airom.internal",
		Namespace:   "production",
		AgentName:   "financial-summarizer",
		ModelBound:  "gpt-4o",
		Scopes:      []string{"read:aibom", "invoke:gateway"},
	}

	cred := attestor.IssueSVID(agentID, 1*time.Hour)
	if cred.SPIFFEID != "spiffe://airom.internal/ns/production/agent/financial-summarizer" {
		t.Errorf("unexpected SPIFFE ID: %s", cred.SPIFFEID)
	}

	verifiedID, err := attestor.VerifySVID(cred.Token)
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if verifiedID != cred.SPIFFEID {
		t.Errorf("verified ID mismatch: %s vs %s", verifiedID, cred.SPIFFEID)
	}
}

func TestIdentity_ExpiredSVID(t *testing.T) {
	attestor := NewAttestor("airom.internal", "secret-signing-key")

	agentID := AgentIdentity{
		SPIFFEID: attestor.FormatSPIFFEID("default", "short-lived-agent"),
	}

	// Issue token with -1 second TTL (already expired)
	cred := attestor.IssueSVID(agentID, -1*time.Second)

	_, err := attestor.VerifySVID(cred.Token)
	if err == nil {
		t.Fatalf("expected error on expired token")
	}
}

func TestIdentity_TrustDomainMismatch(t *testing.T) {
	attestorA := NewAttestor("domain-a.org", "shared-key")
	attestorB := NewAttestor("domain-b.org", "shared-key")

	agentID := AgentIdentity{
		SPIFFEID: "spiffe://domain-a.org/ns/default/agent/agent-1",
	}

	cred := attestorA.IssueSVID(agentID, 1*time.Hour)

	// Verify using attestor B with domain-b
	_, err := attestorB.VerifySVID(cred.Token)
	if err == nil {
		t.Fatalf("expected trust domain mismatch error")
	}
}
