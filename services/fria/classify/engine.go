package classify

import (
	"strings"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Engine performs statutory EU AI Act classification.
type Engine struct{}

// NewEngine constructs a classification engine.
func NewEngine() *Engine {
	return &Engine{}
}

// ClassifySystem determines the EU AI Act risk tier for an inventory and deployment purpose.
func (e *Engine) ClassifySystem(systemName, deploymentDomain string, inv *airom.Inventory) ClassificationResult {
	lowerDomain := strings.ToLower(deploymentDomain)

	// 1. Check Article 5 Prohibited Practices (Social Scoring, Real-time Public Biometric Identification, Subliminal Manipulation)
	if strings.Contains(lowerDomain, "social_scoring") || strings.Contains(lowerDomain, "subliminal") || strings.Contains(lowerDomain, "real_time_public_biometric") {
		return ClassificationResult{
			SystemName:       systemName,
			Tier:             TierUnacceptableRisk,
			StatutoryBasis:   "EU AI Act Article 5 (Prohibited AI Practices)",
			ProhibitedReason: "Deployment involves unacceptable risk prohibited by law across the European Union.",
			MandatoryActions: []string{"Immediate decommissioning / Prohibited from placing on the EU market"},
			ClassifiedAt:     time.Now().UTC(),
		}
	}

	// 2. Check Annex III High-Risk Categories
	var annexCat *AnnexIIICategory

	switch {
	case strings.Contains(lowerDomain, "biometric") || strings.Contains(lowerDomain, "facial_recognition"):
		cat := AnnexIII_1_Biometrics
		annexCat = &cat
	case strings.Contains(lowerDomain, "critical_infra") || strings.Contains(lowerDomain, "energy_grid") || strings.Contains(lowerDomain, "water_supply"):
		cat := AnnexIII_2_CriticalInfra
		annexCat = &cat
	case strings.Contains(lowerDomain, "education") || strings.Contains(lowerDomain, "student_evaluation") || strings.Contains(lowerDomain, "exam_proctoring"):
		cat := AnnexIII_3_EducationVocational
		annexCat = &cat
	case strings.Contains(lowerDomain, "hr") || strings.Contains(lowerDomain, "recruitment") || strings.Contains(lowerDomain, "workforce") || strings.Contains(lowerDomain, "resume_screening"):
		cat := AnnexIII_4_EmploymentHR
		annexCat = &cat
	case strings.Contains(lowerDomain, "credit_scoring") || strings.Contains(lowerDomain, "insurance_pricing") || strings.Contains(lowerDomain, "emergency_dispatch"):
		cat := AnnexIII_5_EssentialServices
		annexCat = &cat
	case strings.Contains(lowerDomain, "law_enforcement") || strings.Contains(lowerDomain, "crime_analytics") || strings.Contains(lowerDomain, "polygraph"):
		cat := AnnexIII_6_LawEnforcement
		annexCat = &cat
	case strings.Contains(lowerDomain, "asylum") || strings.Contains(lowerDomain, "visa_application") || strings.Contains(lowerDomain, "border_control"):
		cat := AnnexIII_7_MigrationAsylum
		annexCat = &cat
	case strings.Contains(lowerDomain, "judicial") || strings.Contains(lowerDomain, "court_sentencing") || strings.Contains(lowerDomain, "election"):
		cat := AnnexIII_8_DemocraticProcesses
		annexCat = &cat
	}

	if annexCat != nil {
		return ClassificationResult{
			SystemName:       systemName,
			Tier:             TierHighRisk,
			AnnexIIICategory: annexCat,
			StatutoryBasis:   "EU AI Act Article 6(2) & Annex III",
			MandatoryActions: []string{
				"Conduct Fundamental Rights Impact Assessment (FRIA) pursuant to Article 27",
				"Establish Risk Management System pursuant to Article 9",
				"Ensure Data Governance & Training Data Quality pursuant to Article 10",
				"Draw up Technical Documentation & Conformity Assessment pursuant to Article 11 & Article 43",
				"Register in EU High-Risk AI System Database pursuant to Article 71",
				"Affix CE Marking of Conformity pursuant to Article 48",
			},
			ClassifiedAt: time.Now().UTC(),
		}
	}

	// 3. Check Article 50 Generative / Synthetic Content Transparency
	hasGenerative := false
	if inv != nil {
		for _, c := range inv.Components {
			if c.Kind == airom.KindHostedLLM || c.Kind == airom.KindPrompt || (c.Model != nil && c.Model.Task.V == "text-generation") {
				hasGenerative = true
				break
			}
		}
	}

	if hasGenerative || strings.Contains(lowerDomain, "generative") || strings.Contains(lowerDomain, "chatbot") {
		return ClassificationResult{
			SystemName:     systemName,
			Tier:           TierSpecificTransparency,
			StatutoryBasis: "EU AI Act Article 50 (Transparency Obligations for Generative AI)",
			MandatoryActions: []string{
				"Inform natural persons that they are interacting with an AI system",
				"Mark AI-generated text and synthetic audio/video in a machine-readable format (Token Watermarking)",
				"Publish summary of copyright training data",
			},
			ClassifiedAt: time.Now().UTC(),
		}
	}

	// 4. Minimal Risk Default
	return ClassificationResult{
		SystemName:     systemName,
		Tier:           TierMinimalRisk,
		StatutoryBasis: "EU AI Act Article 69 (Minimal / Low Risk AI)",
		MandatoryActions: []string{
			"Adhere to voluntary codes of conduct",
			"Maintain general AI literacy for staff pursuant to Article 4",
		},
		ClassifiedAt: time.Now().UTC(),
	}
}
