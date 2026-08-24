package plugin

import (
	"testing"
	"time"
)

func TestQA_AdversarialForgedHandshakeHMAC(t *testing.T) {
	transport := NewTransport("secret_key_1")

	forgedReq := HandshakeRequest{
		ProtocolVersion: ProtocolVersion,
		MagicToken:      MagicHandshakeToken,
		HostVersion:     "1.0.0",
		AuthHMAC:        "forged_hmac_hex_token_9999",
		Timestamp:       time.Now().UTC(),
	}

	if err := transport.VerifyHandshake(forgedReq); err == nil {
		t.Fatalf("expected error on forged HMAC token, got nil")
	}
}

func TestQA_AdversarialUnregisteredMethodExecution(t *testing.T) {
	transport := NewTransport("secret")

	msg := PluginMessage{
		ID:      "evil-1",
		Method:  "system.eval_arbitrary_code",
		Payload: []byte("rm -rf /"),
	}

	resp, err := transport.Call(msg)
	if err == nil || !resp.IsError {
		t.Fatalf("expected error on unregistered method, got response: %+v", resp)
	}
}

func TestQA_AdversarialVersionNegotiationMismatch(t *testing.T) {
	transport := NewTransport("secret")

	mismatchedReq := HandshakeRequest{
		ProtocolVersion: "99.0.0", // Unsupported future protocol
		MagicToken:      MagicHandshakeToken,
		HostVersion:     "1.0.0",
		AuthHMAC:        transport.ComputeAuthHMAC(MagicHandshakeToken, time.Now().UTC()),
		Timestamp:       time.Now().UTC(),
	}

	if err := transport.VerifyHandshake(mismatchedReq); err == nil {
		t.Fatalf("expected error on protocol version mismatch")
	}
}
