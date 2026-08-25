package cloudstream

import (
	"testing"
)

func TestQA_AdversarialForgedSignatures(t *testing.T) {
	streamer := NewStreamer([]byte("real-secret-key-12345"), 100)
	fakeStreamer := NewStreamer([]byte("attacker-secret-key-54321"), 100)

	fakeEvt := fakeStreamer.IngestEvent(DestGoogleChronicle, "target-org", "target-repo", "DATA_EXFIL", SeverityCritical, "Spoofed", "Forged log")

	if streamer.VerifyEventSignature(*fakeEvt) {
		t.Fatalf("SECURITY VIOLATION: streamer accepted signature signed with a different key")
	}
}

func TestQA_AdversarialEmptyStrings(t *testing.T) {
	streamer := NewStreamer(nil, 0)
	evt := streamer.IngestEvent(DestSplunkHEC, "", "", "", SeverityInfo, "", "")

	if !streamer.VerifyEventSignature(*evt) {
		t.Fatalf("expected valid signature on empty strings")
	}
}
