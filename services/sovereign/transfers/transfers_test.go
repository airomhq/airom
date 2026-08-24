package transfers

import (
	"testing"
)

func TestTransfer_EU_To_US_WithDPF(t *testing.T) {
	gate := NewGate()

	req := TransferRequest{
		TransferID:       "t-dpf",
		Origin:           JurisdictionEU_EEA,
		Destination:      JurisdictionUS,
		DataPayloadType:  "prompt_inference_stream",
		ContainsPII:      true,
		MechanismClaimed: MechanismEU_US_DPF,
	}

	dec := gate.EvaluateTransfer(req)
	if !dec.Approved {
		t.Errorf("expected approval under EU-US DPF: %+v", dec)
	}
}

func TestTransfer_EU_To_US_Unauthorized(t *testing.T) {
	gate := NewGate()

	req := TransferRequest{
		TransferID:       "t-unauth",
		Origin:           JurisdictionEU_EEA,
		Destination:      JurisdictionUS,
		DataPayloadType:  "training_dataset",
		ContainsPII:      true,
		MechanismClaimed: MechanismNone,
	}

	dec := gate.EvaluateTransfer(req)
	if dec.Approved {
		t.Errorf("expected rejection on unauthorized transfer without safeguards")
	}
}

func TestTransfer_SanctionedJurisdiction(t *testing.T) {
	gate := NewGate()

	req := TransferRequest{
		TransferID:  "t-sanction",
		Origin:      JurisdictionUS,
		Destination: JurisdictionSanctioned,
	}

	dec := gate.EvaluateTransfer(req)
	if dec.Approved {
		t.Errorf("expected hard block for sanctioned destination")
	}
}

func TestTransfer_ChinaCACRequirement(t *testing.T) {
	gate := NewGate()

	// China outbound without CAC approval -> Blocked
	req1 := TransferRequest{
		TransferID:       "t-china-unauth",
		Origin:           JurisdictionChina,
		Destination:      JurisdictionUS,
		MechanismClaimed: MechanismNone,
	}
	dec1 := gate.EvaluateTransfer(req1)
	if dec1.Approved {
		t.Errorf("expected block on China transfer without CAC approval")
	}

	// China outbound with CAC approval -> Approved
	req2 := TransferRequest{
		TransferID:       "t-china-auth",
		Origin:           JurisdictionChina,
		Destination:      JurisdictionUS,
		MechanismClaimed: MechanismChinaCACApproval,
	}
	dec2 := gate.EvaluateTransfer(req2)
	if !dec2.Approved {
		t.Errorf("expected approval with CAC approval")
	}
}
