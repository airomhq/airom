package commercial

import (
	"testing"
	"time"

	"github.com/airomhq/airom/internal/openssf/scorecard"
	"github.com/airomhq/airom/pkg/airom"
	"github.com/airomhq/airom/services/cloud/aws"
	"github.com/airomhq/airom/services/cloud/azure"
	"github.com/airomhq/airom/services/cloud/gcp"
	"github.com/airomhq/airom/services/commercial/marketplace"
	"github.com/airomhq/airom/services/itsm/bidirectional"
	"github.com/airomhq/airom/services/itsm/remediation"
	"github.com/airomhq/airom/services/regwatch/calendar"
	"github.com/airomhq/airom/services/regwatch/impact"
	"github.com/airomhq/airom/services/regwatch/webhook"
	"github.com/airomhq/airom/services/saas/pdf"
	"github.com/airomhq/airom/services/saas/sse"
	"github.com/airomhq/airom/services/saas/tenant"
	"github.com/airomhq/airom/services/siem/cloudstream"
)

func TestMaster_EnterpriseAndCommercialEcosystem_EndToEnd(t *testing.T) {
	// ── 1. MULTI-TENANT SAAS ONBOARDING (Sprint 82) ──
	tenantMgr := tenant.NewManager()
	org, err := tenantMgr.CreateOrganization("org-yc-scale", "Sovereign Enterprise Corp", tenant.TierSovereign)
	if err != nil || org == nil {
		t.Fatalf("failed to create tenant: %v", err)
	}

	err = tenantMgr.RegisterRepository("org-yc-scale", "repo-enterprise-ai")
	if err != nil {
		t.Fatalf("failed to register repository: %v", err)
	}

	// ── 2. MULTI-CLOUD AI DISCOVERY (Sprints 76, 77, 78) ──
	awsConn := aws.NewConnector()
	azureConn := azure.NewConnector()
	gcpConn := gcp.NewConnector()

	awsRes := awsConn.CompileAIBOM("123456789012", "us-east-1", []aws.BedrockModelSpec{
		{ModelID: "anthropic.claude-3-5-sonnet", ModelName: "Claude 3.5 Sonnet", ProviderName: "Anthropic", Region: "us-east-1"},
	}, nil)

	azureRes := azureConn.CompileAIBOM("sub-123", "tenant-456", []azure.AzureDeploymentSpec{
		{DeploymentName: "gpt-4o-prod", ModelName: "gpt-4o", ModelVersion: "2024-05-13", Region: "eastus"},
	})

	gcpRes := gcpConn.CompileAIBOM("proj-ai", "us-central1", []gcp.VertexEndpointSpec{
		{DisplayName: "gemini-1.5-pro", ModelResourceName: "publishers/google/models/gemini-1.5-pro", Location: "us-central1"},
	})

	if len(awsRes.Inventory.Components) != 1 || len(azureRes.Inventory.Components) != 1 || len(gcpRes.Inventory.Components) != 1 {
		t.Fatalf("cloud discovery counts mismatch")
	}

	// Combine components into unified enterprise AIBOM
	unifiedInv := &airom.Inventory{
		Components: append(awsRes.Inventory.Components, append(azureRes.Inventory.Components, gcpRes.Inventory.Components...)...),
	}

	if len(unifiedInv.Components) != 3 {
		t.Fatalf("expected 3 combined multi-cloud components, got %d", len(unifiedInv.Components))
	}

	// ── 3. OPENSSF AI MODEL SECURITY SCORECARDS (Sprint 88) ──
	openssfEval := scorecard.NewEvaluator()
	scReport := openssfEval.EvaluateInventory(unifiedInv)
	if scReport.TotalModels != 3 {
		t.Errorf("expected 3 OpenSSF model scorecards, got %d", scReport.TotalModels)
	}

	// ── 4. STATUTORY BLAST RADIUS & LEGISLATIVE ALERTS (Sprints 85, 86, 87) ──
	impactEval := impact.NewEvaluator()
	impactAssessment := impactEval.EvaluateInventory("CA-SB1047", unifiedInv)
	if impactAssessment == nil || impactAssessment.TotalComponents != 3 {
		t.Errorf("impact assessment failed")
	}

	calendarPipeline := calendar.NewPipeline()
	notices := calendarPipeline.ComputeActionNotices(time.Now().UTC())
	if len(notices) < 3 {
		t.Errorf("expected at least 3 statutory action notices")
	}

	webhookDispatcher := webhook.NewDispatcher()
	webhookDispatcher.RegisterSubscriber(webhook.SubscriberWebhook{
		SubscriberID:     "enterprise-compliance-ops",
		SecretKey:        "sig-key-123",
		SubscribedStates: []string{"ALL"},
	})
	dispatches := webhookDispatcher.DispatchBillEvent(webhook.BillProgressionEvent{
		BillID:       "CA-SB1047",
		Jurisdiction: "California",
		CurrentStage: webhook.StageFloorVote,
	})
	if len(dispatches) != 1 {
		t.Errorf("expected 1 webhook delivery")
	}

	// ── 5. ENTERPRISE ITSM & AUTOMATED REMEDIATION (Sprints 79, 80) ──
	itsmCoord := bidirectional.NewCoordinator()
	ticket := itsmCoord.OnGapDetected(bidirectional.PlatformJira, "repo-enterprise-ai", "EU-AI-ACT-10", "HIGH", "Missing dataset documentation")
	if ticket.Status != bidirectional.StatusOpen {
		t.Errorf("expected open ITSM ticket")
	}

	remedEngine := remediation.NewEngine()
	remPlan := remedEngine.CreateRemediationPlan("repo-enterprise-ai", map[string]string{
		"src/model_caller.py": "client.chat(model='gpt-3.5-turbo-0613')\n",
	})
	if remPlan == nil || len(remPlan.Patches) != 1 {
		t.Errorf("expected automated upgrade remediation plan")
	}

	// Auto-resolve ITSM ticket
	closedTk, resolved := itsmCoord.OnGapResolved("repo-enterprise-ai", "EU-AI-ACT-10")
	if !resolved || closedTk.Status != bidirectional.StatusAutoClosed {
		t.Errorf("expected ticket auto-closed")
	}

	// ── 6. REAL-TIME SSE & CLOUD SIEM STREAMING (Sprints 81, 83) ──
	sseBroadcaster := sse.NewBroadcaster(10)
	client := sseBroadcaster.Subscribe("admin-cockpit-1", "org-yc-scale")
	defer sseBroadcaster.Unsubscribe("admin-cockpit-1")

	_ = sseBroadcaster.Publish("org-yc-scale", sse.EventScanCompleted, "Multi-cloud scan conformant")

	select {
	case sseMsg := <-client.Channel:
		if sseMsg.Type != sse.EventScanCompleted {
			t.Errorf("unexpected SSE message: %+v", sseMsg)
		}
	default:
		t.Errorf("expected SSE event on client channel")
	}

	siemStreamer := cloudstream.NewStreamer([]byte("corp-siem-secret"), 10)
	siemEvt := siemStreamer.IngestEvent(cloudstream.DestSplunkHEC, "org-yc-scale", "repo-enterprise-ai", "SCAN_CONFORMANT", cloudstream.SeverityInfo, "Scan Clean", "All 3 cloud models conformant")
	if !siemStreamer.VerifyEventSignature(*siemEvt) {
		t.Errorf("SIEM HMAC signature verification failed")
	}

	// ── 7. EXECUTIVE PDF REPORT GENERATION (Sprint 84) ──
	pdfGen := pdf.NewGenerator()
	pdfDossier := pdfGen.GeneratePDF(pdf.DocumentSpec{
		Title:            "Executive AI Governance Dossier",
		OrganizationName: "Sovereign Enterprise Corp",
		RepositoryName:   "repo-enterprise-ai",
		FrameworkName:    "Multi-Cloud Governance & EU AI Act",
		ExecutiveSummary: "Multi-cloud discovery and OpenSSF audit completed with zero critical gaps.",
		TotalComponents:  3,
		ControlsMet:      3,
		GapsIdentified:   0,
		GeneratedAt:      time.Now().UTC(),
	})
	if pdfDossier == nil || len(pdfDossier.PDFBytes) == 0 {
		t.Errorf("PDF dossier generation failed")
	}

	// ── 8. CLOUD MARKETPLACE METERING (Sprint 89) ──
	meter := marketplace.NewMeter()
	_, err = meter.IngestUsage(marketplace.ProviderAWS, "cust-aws-enterprise", marketplace.DimensionModelScans, 1, "idem-scan-1")
	if err != nil {
		t.Errorf("marketplace metering failed: %v", err)
	}

	mBatch := meter.FlushBatch(marketplace.ProviderAWS)
	if mBatch == nil || mBatch.TotalUnits != 1 {
		t.Errorf("expected marketplace batch of 1 unit")
	}
}
