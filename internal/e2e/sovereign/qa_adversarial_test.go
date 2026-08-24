package sovereign

import (
	"testing"

	"github.com/airomhq/airom/services/sovereign/exportcontrol"
	"github.com/airomhq/airom/services/sovereign/matrix"
	"github.com/airomhq/airom/services/sovereign/transfers"
	"github.com/airomhq/airom/services/swarm/circuit"
	"github.com/airomhq/airom/services/swarm/poa"
)

func TestQA_AdversarialMultiThreatE2E(t *testing.T) {
	// 1. Swarm Circuit with runaway hop depth
	breaker := circuit.NewBreaker(circuit.SafetyCeilings{MaxHopDepth: 3})
	_ = breaker.AllowDelegation(circuit.DelegationCall{CurrentHop: 10})
	if breaker.Status().State != circuit.StateOpen {
		t.Errorf("expected circuit tripped to OPEN")
	}

	// 2. POA Gate with negative financial amount
	poaGate := poa.NewGate()
	poaGate.RegisterGrant(poa.POAGrant{AgentID: "agent-evil", AuthorizedScopes: []poa.POAScope{poa.ScopeFinancialPayment}})
	dec := poaGate.EvaluateAction(poa.ActionRequest{AgentID: "agent-evil", Scope: poa.ScopeFinancialPayment, AmountUSD: -9999.0})
	if dec.Approved {
		t.Errorf("expected negative amount rejected")
	}

	// 3. Transfer Gate to sanctioned jurisdiction
	transferGate := transfers.NewGate()
	tDec := transferGate.EvaluateTransfer(transfers.TransferRequest{Destination: transfers.JurisdictionSanctioned})
	if tDec.Approved {
		t.Errorf("expected sanctioned transfer rejected")
	}

	// 4. Export Control for embargoed country
	exportEngine := exportcontrol.NewEngine()
	eRes := exportEngine.ScreenModel(exportcontrol.ModelExportSpec{DestinationCountry: "cuba"})
	if eRes.Requirement != exportcontrol.ProhibitedDenied {
		t.Errorf("expected embargoed country prohibited")
	}

	// 5. Global Matrix for prohibited AI
	harmonizer := matrix.NewHarmonizer()
	mRes := harmonizer.Harmonize("Evil-System", "social_scoring", nil)
	if mRes.OverallVerdict != "PROHIBITED" {
		t.Errorf("expected social scoring prohibited")
	}
}
