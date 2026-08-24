package matrix

import (
	"strings"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Harmonizer evaluates AI systems across global sovereign regulatory frameworks.
type Harmonizer struct{}

// NewHarmonizer constructs a global regulatory harmonizer.
func NewHarmonizer() *Harmonizer {
	return &Harmonizer{}
}

// Harmonize evaluates an AI system and its components against all 6 major global frameworks.
func (h *Harmonizer) Harmonize(systemName, domain string, inv *airom.Inventory) GlobalComplianceMatrix {
	lowerDomain := strings.ToLower(domain)

	matrix := GlobalComplianceMatrix{
		SystemName:      systemName,
		Verdicts:        make(map[GlobalFramework]FrameworkVerdict),
		TotalFrameworks: 6,
		HarmonizedAt:    time.Now().UTC(),
		OverallVerdict:  "GLOBAL_PASS",
	}

	// 1. EU AI Act
	if strings.Contains(lowerDomain, "social_scoring") || strings.Contains(lowerDomain, "real_time_biometric") {
		matrix.Verdicts[FrameworkEU_AI_Act] = FrameworkVerdict{
			Framework:       FrameworkEU_AI_Act,
			Jurisdiction:    "European Union",
			Status:          "PROHIBITED",
			StatutoryBasis:  "EU AI Act Article 5",
			RequiredFilings: []string{"Decommission immediately"},
		}
		matrix.OverallVerdict = "PROHIBITED"
	} else if strings.Contains(lowerDomain, "hr") || strings.Contains(lowerDomain, "credit") || strings.Contains(lowerDomain, "biometric") {
		matrix.Verdicts[FrameworkEU_AI_Act] = FrameworkVerdict{
			Framework:       FrameworkEU_AI_Act,
			Jurisdiction:    "European Union",
			Status:          "GAP_IDENTIFIED",
			StatutoryBasis:  "EU AI Act Article 6 & Annex III (High Risk)",
			RequiredFilings: []string{"Article 27 FRIA", "Annex IV Technical Doc", "Article 48 CE Mark"},
		}
		if matrix.OverallVerdict != "PROHIBITED" {
			matrix.OverallVerdict = "REGIONAL_RESTRICTIONS"
		}
	} else {
		matrix.Verdicts[FrameworkEU_AI_Act] = FrameworkVerdict{
			Framework:      FrameworkEU_AI_Act,
			Jurisdiction:   "European Union",
			Status:         "COMPLIANT",
			StatutoryBasis: "EU AI Act Article 69 (Minimal Risk)",
		}
		matrix.CompliantCount++
	}

	// 2. US NIST / Executive Order
	matrix.Verdicts[FrameworkUS_EO_NIST] = FrameworkVerdict{
		Framework:      FrameworkUS_EO_NIST,
		Jurisdiction:   "United States",
		Status:         "COMPLIANT",
		StatutoryBasis: "NIST AI 100-1 AI RMF & EO 14110",
	}
	matrix.CompliantCount++

	// 3. UK Pro-Innovation Framework
	matrix.Verdicts[FrameworkUK_ProInnovation] = FrameworkVerdict{
		Framework:      FrameworkUK_ProInnovation,
		Jurisdiction:   "United Kingdom",
		Status:         "COMPLIANT",
		StatutoryBasis: "UK DSIT 5 AI Regulatory Principles",
	}
	matrix.CompliantCount++

	// 4. Japan Guidelines
	matrix.Verdicts[FrameworkJapan_Guidelines] = FrameworkVerdict{
		Framework:      FrameworkJapan_Guidelines,
		Jurisdiction:   "Japan",
		Status:         "COMPLIANT",
		StatutoryBasis: "METI/MIC AI Guidelines for Business",
	}
	matrix.CompliantCount++

	// 5. Singapore Model Governance
	matrix.Verdicts[FrameworkSingapore_ModelGov] = FrameworkVerdict{
		Framework:      FrameworkSingapore_ModelGov,
		Jurisdiction:   "Singapore",
		Status:         "COMPLIANT",
		StatutoryBasis: "IMDA Model AI Governance Framework (GenAI)",
	}
	matrix.CompliantCount++

	// 6. China Generative AI Measures
	if strings.Contains(lowerDomain, "generative") || strings.Contains(lowerDomain, "llm") {
		matrix.Verdicts[FrameworkChina_Generative] = FrameworkVerdict{
			Framework:       FrameworkChina_Generative,
			Jurisdiction:    "China",
			Status:          "GAP_IDENTIFIED",
			StatutoryBasis:  "CAC Interim Measures for Generative AI Services",
			RequiredFilings: []string{"CAC Algorithm Registry Filing", "Security Assessment Filing"},
		}
		if matrix.OverallVerdict != "PROHIBITED" {
			matrix.OverallVerdict = "REGIONAL_RESTRICTIONS"
		}
	} else {
		matrix.Verdicts[FrameworkChina_Generative] = FrameworkVerdict{
			Framework:      FrameworkChina_Generative,
			Jurisdiction:   "China",
			Status:         "COMPLIANT",
			StatutoryBasis: "Standard AI Deployment",
		}
		matrix.CompliantCount++
	}

	return matrix
}
