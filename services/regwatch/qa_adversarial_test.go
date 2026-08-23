package regwatch

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ============================================================================
// TEST 1: Adversarial Malformed Feed Injection
// ============================================================================
func TestQA_AdversarialMalformedFeedInjection(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		handler          http.HandlerFunc
		expectFallback   bool
		verifyDocContent func(t *testing.T, doc *StatutoryDocument)
	}{
		{
			name: "Corrupted_JSON_Payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jurisdiction": "CO-AG", "title": "Malformed", "sections": [{"id": "bad", "content": `)) // malformed EOF
			},
			expectFallback: true,
		},
		{
			name: "HTTP_500_Internal_Server_Error_HTML",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body><h1>Database Error</h1><p>Connection pool exhausted</p></body></html>`))
			},
			expectFallback: true,
		},
		{
			name: "Truncated_HTTP_Stream",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"jurisdiction": "CO-`))
				// Flusher close or abrupt end
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			},
			expectFallback: true,
		},
		{
			name: "SQL_Injection_In_Payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				advDoc := StatutoryDocument{
					Jurisdiction:  JurisdictionColorado,
					Title:         "CO SB 24-205'; DROP TABLE statutory_rules; --",
					SourceURL:     "https://leg.colorado.gov/bills/sb24-205?q=' OR 1=1 --",
					Version:       "2026.1'; EXEC xp_cmdshell('dir');--",
					EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					Sections: []StatuteSection{
						{
							ID:      "[ev:'; DROP TABLE statutory_rules--:1]",
							Title:   "SQLi Title ' UNION SELECT username, password FROM users --",
							Content: "A deployer shall exercise reasonable care -- '; DROP DATABASE airom; --",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(advDoc)
			},
			expectFallback: false,
			verifyDocContent: func(t *testing.T, doc *StatutoryDocument) {
				if doc.Title != "CO SB 24-205'; DROP TABLE statutory_rules; --" {
					t.Errorf("expected SQL injection string intact in document title, got: %s", doc.Title)
				}
				if len(doc.Sections) != 1 || doc.Sections[0].ID != "[ev:'; DROP TABLE statutory_rules--:1]" {
					t.Errorf("expected SQLi section preserved without crash, got: %v", doc.Sections)
				}
				if doc.DocumentHash == "" {
					t.Error("expected non-empty document hash for SQLi payload")
				}
			},
		},
		{
			name: "XSS_Cross_Site_Scripting_Payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				advDoc := StatutoryDocument{
					Jurisdiction:  JurisdictionColorado,
					Title:         "<script>alert('XSS-TITLE')</script><svg/onload=alert('document.cookie')>",
					SourceURL:     "javascript:alert(document.domain)",
					Version:       "2026.<script>alert(1)</script>",
					EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					Sections: []StatuteSection{
						{
							ID:      "<script>alert('SEC-ID')</script>",
							Title:   "<img src=x onerror=alert('IMG-XSS')>",
							Content: "A deployer <iframe src='javascript:alert(1)'></iframe> shall prevent algorithmic discrimination.",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(advDoc)
			},
			expectFallback: false,
			verifyDocContent: func(t *testing.T, doc *StatutoryDocument) {
				if !strings.Contains(doc.Title, "<script>alert") {
					t.Errorf("expected XSS payload preserved as text, got: %s", doc.Title)
				}
				if doc.DocumentHash == "" {
					t.Error("expected valid hash computed over XSS payload")
				}
			},
		},
		{
			name: "Unicode_Homoglyphs_And_RTL_Overrides",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				// Cyrillic 'а', 'о', 'е' mixed with Latin + zero width spaces and RTL overrides
				advDoc := StatutoryDocument{
					Jurisdiction:  JurisdictionColorado,
					Title:         "Соlоrаdо \u200B Аrtifiсiаl \u202E Intelligence \u202C Act \U0001F600",
					SourceURL:     "https://leg.colorado.gov/bills/\u200Bsb24-205",
					Version:       "2026.1-\uFEFF-v2",
					EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					Sections: []StatuteSection{
						{
							ID:      "6-1-\u200B1703(1)(a)",
							Title:   "Duty оf Rеаsоnаblе Саrе \u200D\u2696\uFE0F",
							Content: "А dерlоуеr оf а high-risk аrtifiсiаl intеlligеnсе sуstеm shаll ехеrсisе rеаsоnаblе саrе.",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(advDoc)
			},
			expectFallback: false,
			verifyDocContent: func(t *testing.T, doc *StatutoryDocument) {
				if doc.DocumentHash == "" {
					t.Error("expected valid hash computed for unicode homoglyphs")
				}
				if len(doc.Sections) != 1 {
					t.Fatalf("expected 1 section, got %d", len(doc.Sections))
				}
			},
		},
		{
			name: "Null_Bytes_In_Payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				advDoc := StatutoryDocument{
					Jurisdiction:  JurisdictionColorado,
					Title:         "Colorado AI Act\x00NullByteInTitle",
					SourceURL:     "https://leg.colorado.gov/\x00/sb24-205",
					Version:       "2026.1\x00admin",
					EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					Sections: []StatuteSection{
						{
							ID:      "6-1-1703\x00(1)(a)",
							Title:   "Risk Management\x00Policy",
							Content: "Null byte embedded in legal content \x00 deployer shall exercise reasonable care.",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(advDoc)
			},
			expectFallback: false,
			verifyDocContent: func(t *testing.T, doc *StatutoryDocument) {
				if doc.DocumentHash == "" {
					t.Error("expected valid hash computed for null-byte payload")
				}
			},
		},
		{
			name: "Path_Traversal_Payload",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				advDoc := StatutoryDocument{
					Jurisdiction:  JurisdictionColorado,
					Title:         "../../../../etc/passwd",
					SourceURL:     "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
					Version:       "../../../../../../var/run/secrets/kubernetes.io/serviceaccount/token",
					EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
					Sections: []StatuteSection{
						{
							ID:      "../../../../etc/shadow",
							Title:   "C:\\Windows\\System32\\cmd.exe",
							Content: "/proc/self/environ deployer shall exercise reasonable care.",
						},
					},
				}
				_ = json.NewEncoder(w).Encode(advDoc)
			},
			expectFallback: false,
			verifyDocContent: func(t *testing.T, doc *StatutoryDocument) {
				if doc.Title != "../../../../etc/passwd" {
					t.Errorf("expected traversal string preserved safely without file read, got: %s", doc.Title)
				}
				if doc.DocumentHash == "" {
					t.Error("expected valid hash computed for path traversal payload")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(tc.handler)
			defer server.Close()

			cfg := ScraperConfig{
				ClientTimeoutSec: 2,
				CustomEndpoints: map[Jurisdiction]string{
					JurisdictionColorado: server.URL,
				},
			}

			scraper := NewRegulatoryScraper(cfg, server.Client())
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			doc, err := scraper.FetchJurisdictionDocument(ctx, JurisdictionColorado)
			if err != nil {
				t.Fatalf("unexpected error (should fall back or succeed cleanly): %v", err)
			}
			if doc == nil {
				t.Fatal("expected non-nil document returned")
			}

			// Baseline verification
			baselineDoc, _ := scraper.GetBuiltinDocument(JurisdictionColorado)

			if tc.expectFallback {
				if doc.Title != baselineDoc.Title {
					t.Errorf("expected fallback to baseline title %q, got %q", baselineDoc.Title, doc.Title)
				}
				if doc.DocumentHash != baselineDoc.DocumentHash {
					t.Errorf("expected fallback hash %q, got %q", baselineDoc.DocumentHash, doc.DocumentHash)
				}
			} else if tc.verifyDocContent != nil {
				tc.verifyDocContent(t, doc)
			}

			// Verify diff engine resilience against this document (zero panics)
			diffEngine := NewDiffEngine()
			diff := diffEngine.ComputeDiff(*baselineDoc, *doc)
			if tc.expectFallback && diff.HasChanges {
				t.Errorf("expected no changes on fallback to baseline, got diff: %+v", diff)
			}
		})
	}
}

// ============================================================================
// TEST 2: Adversarial Statutory Drift & Legislative Tampering Exploits
// ============================================================================
func TestQA_AdversarialStatutoryDriftExploits(t *testing.T) {
	t.Parallel()

	diffEngine := NewDiffEngine()

	baselineDoc := StatutoryDocument{
		Jurisdiction:  JurisdictionColorado,
		Title:         "Colorado AI Act Baseline",
		Version:       "2026.1",
		EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		Sections: []StatuteSection{
			{
				ID:      "6-1-1703(1)(a)",
				Title:   "Duty of Reasonable Care",
				Content: "A deployer of a high-risk artificial intelligence system may voluntarily provide algorithmic impact assessments upon request.",
			},
			{
				ID:      "6-1-1703(1)(b)",
				Title:   "Risk Management Policy",
				Content: "A deployer should implement a general risk management policy.",
			},
			{
				ID:      "6-1-1703(1)(c)",
				Title:   "Compliance Schedule Guidance",
				Content: "General technical guidance regarding standard deployment schedules.",
			},
		},
	}
	baselineDoc.ComputeHash()

	driftTestCases := []struct {
		name             string
		modifiedDoc      StatutoryDocument
		expectedSeverity DeltaSeverity
		expectedChanges  bool
		validateDelta    func(t *testing.T, diff StatutoryDiff)
	}{
		{
			name: "Negation_Inversion_Voluntary_To_Mandatory",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Inversion Attack",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					{
						ID:    "6-1-1703(1)(a)",
						Title: "Duty of Reasonable Care",
						// Inverted: "may voluntarily" -> "must provide mandatory"
						Content: "A deployer of a high-risk artificial intelligence system must provide mandatory algorithmic impact assessments upon request.",
					},
					baselineDoc.Sections[1],
					baselineDoc.Sections[2],
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				found := false
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(a)" {
						found = true
						if d.Severity != SeverityBreaking {
							t.Errorf("expected Section 6-1-1703(1)(a) to be classified BREAKING, got: %s", d.Severity)
						}
						if d.ChangeType != "MODIFIED" {
							t.Errorf("expected change type MODIFIED, got %s", d.ChangeType)
						}
					}
				}
				if !found {
					t.Error("expected section delta for 6-1-1703(1)(a)")
				}
			},
		},
		{
			name: "Penalty_Threshold_Manipulation_Introducing_Fines",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Penalty Injection",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					baselineDoc.Sections[0],
					{
						ID:    "6-1-1703(1)(b)",
						Title: "Risk Management Policy",
						// Injected fine and penalty
						Content: "A deployer should implement a general risk management policy subject to statutory fine and civil penalty for non-compliance.",
					},
					baselineDoc.Sections[2],
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				found := false
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(b)" {
						found = true
						if d.Severity != SeverityBreaking {
							t.Errorf("expected penalty injection to be BREAKING, got: %s", d.Severity)
						}
					}
				}
				if !found {
					t.Error("expected section delta for 6-1-1703(1)(b)")
				}
			},
		},
		{
			name: "Prohibition_Term_Injection",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Prohibition Clause",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					baselineDoc.Sections[0],
					baselineDoc.Sections[1],
					{
						ID:    "6-1-1703(1)(c)",
						Title: "Compliance Schedule Guidance",
						// Injected "prohibit"
						Content: "General technical guidance regarding standard deployment schedules, deployers are prohibited from unapproved rollouts.",
					},
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				found := false
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(c)" {
						found = true
						if d.Severity != SeverityBreaking {
							t.Errorf("expected prohibition term injection to be BREAKING, got: %s", d.Severity)
						}
					}
				}
				if !found {
					t.Error("expected section delta for 6-1-1703(1)(c)")
				}
			},
		},
		{
			name: "Repealed_Section_Sunset_Attack",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Repealed Clause",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				// Section 6-1-1703(1)(a) removed entirely
				Sections: []StatuteSection{
					baselineDoc.Sections[1],
					baselineDoc.Sections[2],
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				found := false
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(a)" {
						found = true
						if d.ChangeType != "REMOVED" {
							t.Errorf("expected ChangeType REMOVED, got %s", d.ChangeType)
						}
						if d.Severity != SeverityBreaking {
							t.Errorf("expected REMOVED section to have BREAKING severity, got %s", d.Severity)
						}
					}
				}
				if !found {
					t.Error("expected removed section delta for 6-1-1703(1)(a)")
				}
			},
		},
		{
			name: "Non_Binding_Technical_Clarification_Update",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Non-Binding Guidance",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					baselineDoc.Sections[0],
					baselineDoc.Sections[1],
					{
						ID:    "6-1-1703(1)(c)",
						Title: "Compliance Schedule Guidance",
						// Minor phrasing tweak with clarification terms, no mandatory words
						Content: "General technical guidance regarding standard deployment schedules and non-binding advisory clarifications.",
					},
				},
			},
			expectedSeverity: SeverityClarification,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(c)" && d.Severity != SeverityClarification {
						t.Errorf("expected CLARIFICATION severity for non-binding technical update, got %s", d.Severity)
					}
				}
			},
		},
		{
			name: "New_Section_Added_With_Mandatory_Audit",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - New Section Enacted",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					baselineDoc.Sections[0],
					baselineDoc.Sections[1],
					baselineDoc.Sections[2],
					{
						ID:      "6-1-1703(1)(d)",
						Title:   "Independent Algorithm Audit",
						Content: "Deployers shall submit all algorithmic systems to mandatory third-party audits.",
					},
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				found := false
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(d)" {
						found = true
						if d.ChangeType != "ADDED" {
							t.Errorf("expected ChangeType ADDED, got %s", d.ChangeType)
						}
						if d.Severity != SeverityBreaking {
							t.Errorf("expected ADDED mandatory clause to be BREAKING, got %s", d.Severity)
						}
					}
				}
				if !found {
					t.Error("expected section delta for newly added 6-1-1703(1)(d)")
				}
			},
		},
		{
			name: "Substantial_Text_Expansion_Over_2x",
			modifiedDoc: StatutoryDocument{
				Jurisdiction:  JurisdictionColorado,
				Title:         "Colorado AI Act - Document Expansion",
				Version:       "2026.2",
				EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
				Sections: []StatuteSection{
					baselineDoc.Sections[0],
					{
						ID:    "6-1-1703(1)(b)",
						Title: "Risk Management Policy",
						// Expand content by >2x length with procedural explanations
						Content: "A deployer should implement a general risk management policy that establishes rigorous baseline procedures, governance frameworks, multi-tiered supervisory committees, stakeholder review intervals, external independent oversight mechanisms, comprehensive data lineage tracking, cross-functional risk matrices, continuous incident notification pipelines, and structured executive sign-off workflows.",
					},
					baselineDoc.Sections[2],
				},
			},
			expectedSeverity: SeverityBreaking,
			expectedChanges:  true,
			validateDelta: func(t *testing.T, diff StatutoryDiff) {
				for _, d := range diff.SectionDeltas {
					if d.SectionID == "6-1-1703(1)(b)" && d.Severity != SeverityBreaking {
						t.Errorf("expected >2x expansion to be classified BREAKING, got %s", d.Severity)
					}
				}
			},
		},
	}

	for _, tc := range driftTestCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.modifiedDoc.ComputeHash()
			diff := diffEngine.ComputeDiff(baselineDoc, tc.modifiedDoc)

			if diff.HasChanges != tc.expectedChanges {
				t.Fatalf("expected HasChanges=%v, got %v", tc.expectedChanges, diff.HasChanges)
			}
			if diff.MaxSeverity != tc.expectedSeverity {
				t.Errorf("expected MaxSeverity=%s, got %s (diff summary: %s)", tc.expectedSeverity, diff.MaxSeverity, diff.Summary)
			}
			if tc.validateDelta != nil {
				tc.validateDelta(t, diff)
			}
		})
	}
}

// ============================================================================
// TEST 3: Adversarial Cross-Jurisdiction Alert Tampering & Isolation
// ============================================================================
func TestQA_AdversarialCrossJurisdictionAlertTampering(t *testing.T) {
	t.Parallel()

	// 1. Fake / Unknown Jurisdiction Rejection
	t.Run("Fake_Jurisdiction_Token_Rejection", func(t *testing.T) {
		svc := NewService(DefaultScraperConfig())

		fakeJurisdictions := []Jurisdiction{
			Jurisdiction("INVALID_JURISDICTION_XXX"),
			Jurisdiction("CN-CAC-AI-2026"),
			Jurisdiction("CO-AG'; DROP TABLE alerts; --"),
			Jurisdiction("EU-AI-OFFICE\x00ADMIN"),
			Jurisdiction("../../rules/fake.yaml"),
		}

		for _, fakeJ := range fakeJurisdictions {
			_, _, err := svc.CheckJurisdiction(context.Background(), fakeJ)
			if err == nil {
				t.Errorf("expected error when checking invalid jurisdiction %q, got nil", fakeJ)
			}
		}
	})

	// 2. Forged Document Hash Detection & Cryptographic Integrity
	t.Run("Forged_Document_Hash_Detection", func(t *testing.T) {
		doc := StatutoryDocument{
			Jurisdiction:  JurisdictionEU,
			Title:         "EU AI Act Tampered",
			Version:       "2026.2",
			EffectiveDate: time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
			DocumentHash:  "0000000000000000000000000000000000000000000000000000000000000000", // Forged hash
			Sections: []StatuteSection{
				{
					ID:          "Article-5",
					Title:       "Prohibited AI Practices",
					Content:     "Tampered content injected into EU article.",
					SectionHash: "1111111111111111111111111111111111111111111111111111111111111111", // Forged section hash
				},
			},
		}

		// Recomputing hash must overwrite forged hashes with true SHA-256
		computedDocHash := doc.ComputeHash()
		if computedDocHash == "0000000000000000000000000000000000000000000000000000000000000000" {
			t.Error("ComputeHash failed to overwrite forged document hash")
		}
		if doc.Sections[0].SectionHash == "1111111111111111111111111111111111111111111111111111111111111111" {
			t.Error("ComputeHash failed to overwrite forged section hash")
		}

		// Determinism check: same content produces identical hash
		hash1 := doc.ComputeHash()
		hash2 := doc.ComputeHash()
		if hash1 != hash2 {
			t.Errorf("non-deterministic hash computation: %s vs %s", hash1, hash2)
		}

		// Perturbation check: 1 character change modifies hash
		doc.Sections[0].Content = "Tampered content injected into EU article!"
		hash3 := doc.ComputeHash()
		if hash3 == hash2 {
			t.Error("hash collision: 1-character modification did not alter document hash")
		}
	})

	// 3. Cross-Jurisdiction Rulepack Mapping Isolation
	t.Run("Cross_Jurisdiction_Rulepack_Isolation", func(t *testing.T) {
		diffEngine := NewDiffEngine()

		jurisdictionRulepackExpectations := map[Jurisdiction]string{
			JurisdictionColorado:   "rules/compliance/co-sb-24-205.yaml",
			JurisdictionCalifornia: "rules/compliance/ca-ab-2013.yaml",
			JurisdictionNYC:        "rules/compliance/nyc-ll144.yaml",
			JurisdictionEU:         "rules/compliance/eu-ai-act.yaml",
			JurisdictionIllinois:   "rules/compliance/il-bipa.yaml",
			JurisdictionTexas:      "rules/compliance/tx-traiga.yaml",
			JurisdictionVirginia:   "rules/compliance/va-vcdpa.yaml",
			JurisdictionUSFederal:  "rules/compliance/nist-ai-rmf.yaml",
		}

		scraper := NewRegulatoryScraper(DefaultScraperConfig(), nil)

		for j, expectedRulepack := range jurisdictionRulepackExpectations {
			doc, err := scraper.GetBuiltinDocument(j)
			if err != nil {
				t.Fatalf("failed to get builtin doc for %s: %v", j, err)
			}

			// Generate modified document
			tamperedDoc := *doc
			tamperedDoc.Version = "2026.99"
			tamperedDoc.Sections = append(tamperedDoc.Sections, StatuteSection{
				ID:      "TAMPER-SEC-1",
				Title:   "Injected Clause",
				Content: "Mandatory new compliance rule.",
			})
			tamperedDoc.ComputeHash()

			diff := diffEngine.ComputeDiff(*doc, tamperedDoc)

			if len(diff.ImpactedRulepacks) != 1 {
				t.Fatalf("jurisdiction %s: expected exactly 1 impacted rulepack, got %d (%v)",
					j, len(diff.ImpactedRulepacks), diff.ImpactedRulepacks)
			}

			if diff.ImpactedRulepacks[0] != expectedRulepack {
				t.Errorf("jurisdiction %s: expected rulepack %s, got %s",
					j, expectedRulepack, diff.ImpactedRulepacks[0])
			}

			// Verify impacted checks have strict jurisdiction prefix
			for _, delta := range diff.SectionDeltas {
				for _, check := range delta.ImpactedChecks {
					if !strings.HasPrefix(check, string(j)+"-RULE-") {
						t.Errorf("jurisdiction %s: check %s does not have proper jurisdiction prefix", j, check)
					}
				}
			}
		}
	})

	// 4. Concurrent Multi-Jurisdiction Alert Dispatcher Isolation & Thread Safety
	t.Run("Concurrent_Multi_Jurisdiction_Alert_Isolation", func(t *testing.T) {
		// Mock server serving custom updates for Colorado and NYC
		mockCODoc := StatutoryDocument{
			Jurisdiction:  JurisdictionColorado,
			Title:         "Colorado Real-Time Update",
			Version:       "2026.9",
			EffectiveDate: time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
			Sections: []StatuteSection{
				{
					ID:      "6-1-1703(1)(a)",
					Title:   "Mandatory Audit Update",
					Content: "Deployers must conduct mandatory audits under penalty of fine.",
				},
			},
		}
		mockCODoc.ComputeHash()

		mockNYCDoc := StatutoryDocument{
			Jurisdiction:  JurisdictionNYC,
			Title:         "NYC Local Law 144 Emergency",
			Version:       "2026.9",
			EffectiveDate: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
			Sections: []StatuteSection{
				{
					ID:      "NYC-LL144-BIAS-AUDIT",
					Title:   "Mandatory Disparity Audit",
					Content: "Employers must submit mandatory bias audit metrics.",
				},
			},
		}
		mockNYCDoc.ComputeHash()

		serverCO := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(mockCODoc)
		}))
		defer serverCO.Close()

		serverNYC := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(mockNYCDoc)
		}))
		defer serverNYC.Close()

		cfg := ScraperConfig{
			ClientTimeoutSec: 2,
			CustomEndpoints: map[Jurisdiction]string{
				JurisdictionColorado: serverCO.URL,
				JurisdictionNYC:      serverNYC.URL,
			},
		}

		svc := NewService(cfg)

		var alertMu sync.Mutex
		receivedAlerts := make(map[Jurisdiction][]RegulatoryAlert)

		svc.SubscribeAlerts(func(alert RegulatoryAlert) {
			alertMu.Lock()
			defer alertMu.Unlock()
			receivedAlerts[alert.Jurisdiction] = append(receivedAlerts[alert.Jurisdiction], alert)
		})

		var wg sync.WaitGroup
		concurrency := 10

		for i := 0; i < concurrency; i++ {
			wg.Add(2)
			go func() {
				defer wg.Done()
				_, _, _ = svc.CheckJurisdiction(context.Background(), JurisdictionColorado)
			}()
			go func() {
				defer wg.Done()
				_, _, _ = svc.CheckJurisdiction(context.Background(), JurisdictionNYC)
			}()
		}

		wg.Wait()
		time.Sleep(50 * time.Millisecond) // Allow alert listener callbacks to finish

		// Validate cache isolation
		cachedCO, okCO := svc.GetCachedDocument(JurisdictionColorado)
		cachedNYC, okNYC := svc.GetCachedDocument(JurisdictionNYC)
		cachedCA, okCA := svc.GetCachedDocument(JurisdictionCalifornia)

		if !okCO || cachedCO.Jurisdiction != JurisdictionColorado {
			t.Errorf("Colorado cache corrupted: %+v", cachedCO)
		}
		if !okNYC || cachedNYC.Jurisdiction != JurisdictionNYC {
			t.Errorf("NYC cache corrupted: %+v", cachedNYC)
		}
		if !okCA || cachedCA.Jurisdiction != JurisdictionCalifornia {
			t.Errorf("California cache unisolated/corrupted: %+v", cachedCA)
		}

		// Validate that CO cache didn't overwrite CA or NYC
		if cachedCO.DocumentHash == cachedNYC.DocumentHash || cachedCO.DocumentHash == cachedCA.DocumentHash {
			t.Errorf("cache document hashes collided across jurisdictions")
		}

		// Verify alerts received
		alertMu.Lock()
		defer alertMu.Unlock()

		for j, alerts := range receivedAlerts {
			for _, a := range alerts {
				if a.Jurisdiction != j {
					t.Errorf("alert jurisdiction mismatch: key %s != alert %s", j, a.Jurisdiction)
				}
				if j == JurisdictionColorado && len(a.ImpactedRulepacks) > 0 && a.ImpactedRulepacks[0] != "rules/compliance/co-sb-24-205.yaml" {
					t.Errorf("Colorado alert leaked non-CO rulepack: %v", a.ImpactedRulepacks)
				}
				if j == JurisdictionNYC && len(a.ImpactedRulepacks) > 0 && a.ImpactedRulepacks[0] != "rules/compliance/nyc-ll144.yaml" {
					t.Errorf("NYC alert leaked non-NYC rulepack: %v", a.ImpactedRulepacks)
				}
			}
		}
	})
}
