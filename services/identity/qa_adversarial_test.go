package identity

import (
	"strings"
	"testing"
	"time"
)

func TestQA_AdversarialForgedSignatures(t *testing.T) {
	attestor := NewAttestor("airom.internal", "real-key")

	agentID := AgentIdentity{
		SPIFFEID: "spiffe://airom.internal/ns/prod/agent/agent-x",
	}
	cred := attestor.IssueSVID(agentID, 1*time.Hour)

	// Bit flip signature in token
	corruptedToken := cred.Token[:len(cred.Token)-4] + "ffff"
	_, err := attestor.VerifySVID(corruptedToken)
	if err == nil {
		t.Fatalf("expected cryptographic rejection of corrupted signature")
	}
}

func TestQA_AdversarialMalformedTokens(t *testing.T) {
	attestor := NewAttestor("airom.internal", "real-key")

	malformedTokens := []string{
		"",
		"single_part_token",
		"too.many.dots.in.token.string",
		"invalid_chars_$$$$.sig",
		strings.Repeat("a", 10000),
	}

	for _, tok := range malformedTokens {
		_, err := attestor.VerifySVID(tok)
		if err == nil {
			t.Errorf("expected error for malformed token: %s", tok)
		}
	}
}
