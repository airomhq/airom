package report

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// citationRegex matches "[ev:<aibom_id>:<file_path>:<line_number>]".
var citationRegex = regexp.MustCompile(`\[ev:([^:\s\]]+):([^:\s\]]+):(\d+)\]`)

// FormatEvidenceKey builds the canonical map key "path:line".
func FormatEvidenceKey(path string, line int) string {
	cleanPath := strings.TrimPrefix(path, "./")
	return fmt.Sprintf("%s:%d", cleanPath, line)
}

// FormatCitation creates a formatted citation tag.
func FormatCitation(aibomID, path string, line int) string {
	cleanPath := strings.TrimPrefix(path, "./")
	return fmt.Sprintf("[ev:%s:%s:%d]", aibomID, cleanPath, line)
}

// ExtractCitations extracts all citation references from a text block.
func ExtractCitations(text string) []Citation {
	matches := citationRegex.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 {
		return nil
	}

	var citations []Citation
	for _, m := range matches {
		lineNum, _ := strconv.Atoi(m[3])
		cleanPath := strings.TrimPrefix(m[2], "./")
		citations = append(citations, Citation{
			RawTag:     m[0],
			AIBOMID:    m[1],
			FilePath:   cleanPath,
			LineNumber: lineNum,
		})
	}
	return citations
}

// isFactualClaim determines if a prose line makes a specific technical or deployment assertion.
func isFactualClaim(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ">") || strings.HasPrefix(trimmed, "---") {
		return false
	}

	// Keywords indicating technical deployment / component claims
	factualKeywords := []string{
		"deploys", "deployed", "utilizes", "utilizing", "implements", "implemented",
		"executes", "configured with", "model weights", "system prompt", "dataset",
		"endpoint", "gpt-", "claude-", "gemini-", "llama-", "mistral-", "scoring engine",
		"inference", "high-risk", "algorithmic", "decision system",
	}

	lower := strings.ToLower(trimmed)
	for _, kw := range factualKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// ValidateReportCitations performs AST verification across prose against an evidence ground truth index.
func ValidateReportCitations(markdownProse string, validEvidence map[EvidenceKey]EvidenceRef) VerifiedProseResult {
	lines := strings.Split(markdownProse, "\n")
	var cleanLines []string
	var allCitations []Citation
	validCount := 0
	invalidCount := 0
	uncitedClaims := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			cleanLines = append(cleanLines, line)
			continue
		}

		matches := citationRegex.FindAllStringSubmatch(line, -1)

		if len(matches) == 0 {
			if isFactualClaim(line) {
				uncitedClaims++
				cleanLines = append(cleanLines, "> [MANUAL ATTESTATION REQUIRED] "+line)
			} else {
				cleanLines = append(cleanLines, line)
			}
			continue
		}

		lineValid := true
		for _, m := range matches {
			rawTag := m[0]
			aibomID := m[1]
			cleanPath := strings.TrimPrefix(m[2], "./")
			lineNum, _ := strconv.Atoi(m[3])
			key := FormatEvidenceKey(cleanPath, lineNum)

			ev, found := validEvidence[key]
			// Also check with relative/full variations
			if !found {
				for evK, candidate := range validEvidence {
					if strings.HasSuffix(evK, key) || (candidate.FilePath == cleanPath && candidate.LineNumber == lineNum) {
						ev = candidate
						found = true
						break
					}
				}
			}

			cit := Citation{
				RawTag:     rawTag,
				AIBOMID:    aibomID,
				FilePath:   cleanPath,
				LineNumber: lineNum,
				IsValid:    found,
			}

			if found {
				cit.Evidence = &ev
				validCount++
			} else {
				cit.ValidationMsg = fmt.Sprintf("no evidence finding at %s:%d", cleanPath, lineNum)
				invalidCount++
				lineValid = false
			}
			allCitations = append(allCitations, cit)
		}

		if lineValid {
			cleanLines = append(cleanLines, line)
		} else {
			cleanLines = append(cleanLines, "> [INVALID CITATION REMOVED] "+citationRegex.ReplaceAllString(line, "[UNVERIFIED CLAIM REMOVED]"))
		}
	}

	status := StatusVerified
	if invalidCount > 0 {
		status = StatusInvalidCitationRemoved
	} else if uncitedClaims > 0 {
		status = StatusRequiresAttestation
	}

	return VerifiedProseResult{
		CleanedProse:       strings.Join(cleanLines, "\n"),
		ExtractedCitations: allCitations,
		ValidCount:         validCount,
		InvalidCount:       invalidCount,
		UncitedClaims:      uncitedClaims,
		AttestationStatus:  status,
	}
}
