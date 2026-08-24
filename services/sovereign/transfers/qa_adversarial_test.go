package transfers

import (
	"testing"
)

func TestQA_AdversarialEmptyTransferRequest(t *testing.T) {
	gate := NewGate()

	dec := gate.EvaluateTransfer(TransferRequest{})
	if dec.TransferID != "" {
		t.Errorf("expected empty transfer ID")
	}
}

func TestQA_AdversarialUnknownJurisdictions(t *testing.T) {
	gate := NewGate()

	dec := gate.EvaluateTransfer(TransferRequest{
		Origin:      "Antarctica",
		Destination: "Mars",
	})

	if !dec.Approved {
		t.Errorf("expected default international exchange policy")
	}
}
