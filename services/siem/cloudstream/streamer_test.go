package cloudstream

import (
	"testing"
)

func TestStreamer_IngestAndFlushBatch(t *testing.T) {
	streamer := NewStreamer([]byte("test-key-12345"), 100)

	evt1 := streamer.IngestEvent(DestSplunkHEC, "org-1", "repo-1", "SHADOW_AI_DETECTED", SeverityHigh, "Shadow AI", "Found undeclared Claude API key")
	evt2 := streamer.IngestEvent(DestDatadogLogs, "org-1", "repo-1", "COMPLIANCE_GAP", SeverityCritical, "Gap", "EU AI Act Annex IV missing")

	if !streamer.VerifyEventSignature(*evt1) {
		t.Fatalf("expected valid HMAC signature on evt1")
	}
	if !streamer.VerifyEventSignature(*evt2) {
		t.Fatalf("expected valid HMAC signature on evt2")
	}

	batchSplunk := streamer.FlushDestination(DestSplunkHEC)
	if batchSplunk == nil || batchSplunk.EventCount != 1 {
		t.Fatalf("expected 1 event in Splunk batch")
	}

	batchDatadog := streamer.FlushDestination(DestDatadogLogs)
	if batchDatadog == nil || batchDatadog.EventCount != 1 {
		t.Fatalf("expected 1 event in Datadog batch")
	}

	// Buffer should be empty after flush
	if empty := streamer.FlushDestination(DestSplunkHEC); empty != nil {
		t.Fatalf("expected nil batch on empty buffer")
	}
}

func TestStreamer_SignatureTamperingDetection(t *testing.T) {
	streamer := NewStreamer([]byte("test-key-12345"), 100)

	evt := streamer.IngestEvent(DestAWSSecurityHub, "org-1", "repo-1", "RED_TEAM_PROBE_ALERT", SeverityCritical, "Prompt Injection", "DAN prompt detected")

	// Tamper with payload
	tamperedEvt := *evt
	tamperedEvt.EventType = "LEGITIMATE_TRAFFIC"

	if streamer.VerifyEventSignature(tamperedEvt) {
		t.Fatalf("expected signature verification to fail on tampered event payload")
	}
}
