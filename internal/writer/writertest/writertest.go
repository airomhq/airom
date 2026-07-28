// Package writertest builds a representative Inventory shared by the writer
// tests and the mapping round-trip test — one fixture exercising every kind,
// tri-state, evidence shape, relationship type, and honesty record, so a
// single golden per format proves the whole projection.
package writertest

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// occ builds an occurrence.
func occ(path string, line int, det string, m airom.DetectionMethod, c float64) airom.Occurrence {
	return airom.Occurrence{
		Location:   airom.Location{Path: path, Line: line, EndLine: line, Column: 5, EndColumn: 20},
		DetectorID: det,
		Method:     m,
		Confidence: airom.Confidence(c),
		Snippet:    "model = \"gpt-4.1\"",
	}
}

// BuildFixture returns a deterministic inventory covering the writer
// surface. Serial and Timestamp are fixed so goldens are byte-stable.
func BuildFixture() *airom.Inventory {
	ts := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)

	root := airom.Component{
		ID: "airom:0000000000000000", Kind: airom.KindApplication, Name: "ai-app",
		Confidence: 1,
	}
	model := airom.Component{
		ID: "airom:1111111111111111", Kind: airom.KindHostedLLM, Name: "gpt-4.1",
		Provider:   airom.KnownString("openai"),
		Confidence: 0.8738,
		Model:      &airom.ModelFacet{Task: airom.KnownString("text-generation"), Architecture: airom.UnknownString()},
		Props: []airom.KV{
			{Name: "airom:model.provider", Value: "openai"},
			{Name: "airom:model.id", Value: "gpt-4.1"},
			{Name: "airom:param.temperature", Value: "0.2 @ src/rag.py:8"},
		},
		// EOL overlay: a deprecation whose own migration target is on the way
		// out too, so the goldens pin both the lifecycle projection and the
		// replacement-state annotation. Hand-authored (the catalog has its own
		// tests); this fixture proves the writer projection.
		EOL: &airom.Lifecycle{
			State:            airom.EOLDeprecated,
			Announced:        &airom.Date{Year: 2026, Month: 4, Day: 22},
			Shutdown:         &airom.Date{Year: 2026, Month: 10, Day: 23},
			DaysRemaining:    func() *int { d := 98; return &d }(),
			Replacement:      "gpt-4.2",
			ReplacementState: airom.EOLDeprecated,
			Source:           "airom-catalog",
			SourceURL:        "https://example.com/deprecations",
			Verified:         &airom.Date{Year: 2026, Month: 7, Day: 17},
		},
		Evidence: airom.Evidence{
			Occurrences: []airom.Occurrence{
				occ("src/rag.py", 7, "rules/openai/model-literal", airom.MethodSourceCode, 0.85),
				occ("src/rag.py", 8, "rules/openai/chat-call", airom.MethodConfig, 0.7),
			},
			Identity: []airom.IdentityClaim{
				{Field: "name", Value: "gpt-4.1", Confidence: 0.85, Methods: []airom.DetectionMethod{airom.MethodSourceCode}},
			},
		},
	}
	const sha = "abababababababababababababababababababababababababababababababab" // 64 hex chars (schema-valid SHA-256)
	weights := airom.Component{
		ID: "airom:2222222222222222", Kind: airom.KindLocalModelFile, Name: "tiny.gguf",
		Provider:   airom.KnownString("local"),
		PURL:       "pkg:generic/tiny.gguf?checksum=sha256:" + sha,
		Confidence: 1,
		Hashes:     []airom.Hash{{Alg: "SHA-256", Hex: sha}},
		Model:      &airom.ModelFacet{Format: airom.KnownString("gguf")},
		Risks: []airom.ArtifactRisk{{
			ID: airom.RiskPickleImport, Severity: airom.RiskHigh, Detail: []string{"os.system"},
			Occurrence: &airom.Occurrence{Location: airom.Location{Path: "models/tiny.gguf"}, DetectorID: "modelfilex/torch", Method: airom.MethodBinary, Confidence: 0.95},
		}},
		Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "models/tiny.gguf"}, DetectorID: "modelfile/gguf", Method: airom.MethodHash, Confidence: 1}}},
	}
	framework := airom.Component{
		ID: "airom:3333333333333333", Kind: airom.KindFramework, Name: "langchain",
		Version:    airom.KnownString("0.2.1"),
		PURL:       "pkg:pypi/langchain@0.2.1",
		Confidence: 0.985,
		Package:    &airom.PackageFacet{Ecosystem: "pypi"},
		// CVE overlay: one advisory exercising the --cve projection — CVSS v3.1
		// vector/score, an alias, and a fixed version. Hand-authored (the OSV
		// client has its own tests); this fixture proves the writer projection.
		Vulnerabilities: []airom.Vulnerability{{
			ID: "CVE-2024-0001", Aliases: []string{"GHSA-aaaa-bbbb-cccc"},
			Severity: airom.VulnHigh, Score: 7.5,
			Vector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			Summary: "Server-side request forgery in the example loader.",
			Fixed:   "0.2.5", Source: "osv.dev",
			URL: "https://osv.dev/vulnerability/CVE-2024-0001",
		}},
		Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "requirements.txt", Line: 1}, DetectorID: "manifest/pypi-requirements", Method: airom.MethodManifest, Confidence: 0.95}}},
	}
	dataset := airom.Component{
		ID: "airom:4444444444444444", Kind: airom.KindDataset, Name: "squad",
		Confidence: 0.7,
		Data:       &airom.DataFacet{Format: airom.KnownString("jsonl"), SizeBytes: airom.KnownInt64(2048)},
		Evidence:   airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "data/squad.jsonl"}, DetectorID: "dataset/file", Method: airom.MethodFilename, Confidence: 0.7}}},
	}
	vecdb := airom.Component{
		ID: "airom:5555555555555555", Kind: airom.KindVectorDB, Name: "chroma",
		Confidence: 0.7,
		// The queries edge lives in Relationships below; the CDX writer
		// synthesizes the airom:rel.queries property from it (no manual
		// double-encoding).
		Evidence: airom.Evidence{Occurrences: []airom.Occurrence{{Location: airom.Location{Path: "src/rag.py", Line: 12}, DetectorID: "rules/chroma/client", Method: airom.MethodSourceCode, Confidence: 0.7}}},
	}

	// Compliance overlay: one framework exercising every control state — a
	// met control with supporting evidence, a gap with counter-evidence (the
	// risky weights), and a manual control (no score). Hand-authored (the
	// evaluator has its own tests); this fixture proves the projection.
	scoreMet, scoreGap := 1.0, 0.0
	compliance := airom.ComplianceResult{
		Framework: "nist-ai-rmf",
		Name:      "NIST AI Risk Management Framework",
		Version:   "1.0",
		URL:       "https://www.nist.gov/itl/ai-risk-management-framework",
		Controls: []airom.ControlOutcome{
			{
				ID: "MAP-2.1", Title: "AI methods are inventoried and documented", Ref: "https://airc.nist.gov/",
				State: airom.ControlMet, Score: &scoreMet, Rationale: "2 component(s) provide supporting evidence",
				Evidence: []airom.ID{model.ID, framework.ID},
			},
			{
				ID: "MEASURE-2.7", Title: "AI system security and resilience are evaluated",
				State: airom.ControlGap, Score: &scoreGap, Rationale: "1 component(s) constitute a gap",
				Counter: []airom.ID{weights.ID},
			},
			{
				ID: "GOVERN-1.1", Title: "Legal and regulatory requirements are documented",
				State: airom.ControlManual, Rationale: "not automatable by a static scan — requires manual attestation",
			},
		},
	}

	return &airom.Inventory{
		SchemaVersion: "1",
		Tool:          airom.ToolInfo{Name: "airom", Version: "1.0.0", Commit: "abc123", RulesVersion: "builtin", RulesHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Serial:        "urn:uuid:00000000-0000-4000-8000-000000000000",
		Timestamp:     ts,
		Lifecycle:     "pre-build",
		Source:        airom.SourceInfo{Kind: "dir", Target: "/src/ai-app", Git: &airom.GitInfo{Remote: "https://github.com/acme/ai-app.git", Commit: "deadbeef"}},
		Root:          root.ID,
		Components:    []airom.Component{root, model, weights, framework, dataset, vecdb},
		Compliance:    []airom.ComplianceResult{compliance},
		Relationships: []airom.Relationship{
			{From: root.ID, To: framework.ID, Type: airom.RelDependsOn, Confidence: 0.95},
			{From: model.ID, To: dataset.ID, Type: airom.RelTrainedOn, Confidence: 0.8},
			{From: vecdb.ID, To: model.ID, Type: airom.RelQueries, Confidence: 0.6, Evidence: []airom.Occurrence{{Location: airom.Location{Path: "src/rag.py", Line: 12}, DetectorID: "rules/chroma/client", Method: airom.MethodSourceCode, Confidence: 0.6}}},
		},
		Unknowns: []airom.Unknown{{Path: "models/corrupt.safetensors", DetectorID: "modelfile/safetensors", Reason: "header length exceeds file"}},
	}
}
