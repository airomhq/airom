# PRD-05: ReportEngine & Evidence-Anchored Report Generator

> **Status:** APPROVED FOR IMPLEMENTATION
> **Target Sprint:** Sprint 7 & Sprint 8 (Phase 3)
> **Target Service:** services/report/, internal/writer/reportw/
> **Owner:** LLM Applications & Document Systems Engineer

---

## 1. Problem & Objectives
- **Problem:** Legal and compliance officers spend weeks drafting audit reports in Word. LLMs hallucinate false compliance claims if ungrounded.
- **Solution:** A server-side ReportEngine where **every generated assertion is backed by an AST [ev:...] citation**. An AST post-processor strips or flags any claim without proof.
- **Formats:** Typst PDF (publication-grade), WCAG 2.1 AA HTML (for NY LL144 web posting), Word DOCX (with track-changes for legal), Markdown.

---

## 2. Evidence Citation Grammar & Validation

Syntax: [ev:<aibom_id>:<file_path>:<line_number>]
Example: Acme Corp deploys GPT-4o at src/underwriting/scoring.py:47 [ev:aibom_01J:src/underwriting/scoring.py:47].

### AST Verifier Logic:
`go
package report

import (
	"regexp"
	"strings"
)

var citationRegex = regexp.MustCompile(\[ev:([^:]+):([^:]+):(\d+)\])

func ValidateReportCitations(markdownProse string, validEvidence map[string]bool) string {
	lines := strings.Split(markdownProse, "
")
	var cleanLines []string

	for _, line := range lines {
		matches := citationRegex.FindAllStringSubmatch(line, -1)
		if len(matches) == 0 && isFactualClaim(line) {
			cleanLines = append(cleanLines, "> [MANUAL ATTESTATION REQUIRED] "+line)
			continue
		}

		allValid := true
		for _, m := range matches {
			key := m[2] + ":" + m[3] // file:line
			if !validEvidence[key] {
				allValid = false
				break
			}
		}

		if allValid {
			cleanLines = append(cleanLines, line)
		} else {
			cleanLines = append(cleanLines, "> [INVALID CITATION REMOVED]")
		}
	}
	return strings.Join(cleanLines, "
")
}
`

---

## 3. On-Premises Docker Container (BYOK)

Image: irom/report-engine:latest
Config: ~/.airom/config.yaml

`yaml
report_engine:
  endpoint: "https://airom.internal.acme-corp.com/v1"
  llm_backend:
    provider: "anthropic" # openai | azure | ollama
    api_key_env: "ANTHROPIC_API_KEY"
    model: "claude-3-5-sonnet-20241022"
`

---

## 4. Acceptance Criteria
1. 100% of factual assertions in generated PDF link to verifiable evidence.occurrences[].
2. Colorado AI Act report renders in < 15 seconds.
3. Air-gapped on-prem container executes with zero outbound network calls.
