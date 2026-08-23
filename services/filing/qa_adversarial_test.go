package filing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestQA_AdversarialForgedAttestationSignature(t *testing.T) {
	builder := NewPackageBuilder()
	agent := NewFilingAgent(nil)

	opts := BuildPackageOptions{
		Jurisdiction:     JurisdictionColorado,
		OrganizationID:   "org_forgery_test",
		OrganizationName: "Original Corp",
		RepositoryID:     "repo_ai",
		SignerName:       "Legitimate Officer",
		SignerEmail:      "legit@corp.com",
	}

	manifest, err := builder.BuildPackage(opts)
	if err != nil {
		t.Fatalf("failed to build package: %v", err)
	}

	tempDir, err := os.MkdirTemp("", "airom-forgery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	if err := builder.ExportToDirectory(manifest, tempDir); err != nil {
		t.Fatalf("failed to export package: %v", err)
	}

	// Adversarial Attack: Forge the signer name in manifest without updating signature hash
	manifest.Signer.OfficerName = "Attacker Impersonator"
	// Also re-export corrupted manifest
	_ = builder.ExportToDirectory(manifest, tempDir)

	_, err = agent.VerifyPackage(tempDir)
	if err == nil {
		t.Fatal("expected VerifyPackage to reject forged attestation signature, but it passed")
	}
}

func TestQA_AdversarialArtifactTampering(t *testing.T) {
	builder := NewPackageBuilder()
	agent := NewFilingAgent(nil)

	tests := []struct {
		name    string
		tamper  func(pkgDir string, manifest *FilingManifest) error
		errMsg  string
	}{
		{
			name: "Bit-flip in JSON disclosure",
			tamper: func(pkgDir string, manifest *FilingManifest) error {
				path := filepath.Join(pkgDir, manifest.Artifacts[0].RelativePath)
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				content[0] = 'X' // Corrupt opening brace
				return os.WriteFile(path, content, 0644)
			},
			errMsg: "checksum mismatch",
		},
		{
			name: "Appended trailing whitespace to markdown",
			tamper: func(pkgDir string, manifest *FilingManifest) error {
				path := filepath.Join(pkgDir, manifest.Artifacts[1].RelativePath)
				content, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				content = append(content, ' ')
				return os.WriteFile(path, content, 0644)
			},
			errMsg: "checksum mismatch",
		},
		{
			name: "Appended trailing null bytes (size change)",
			tamper: func(pkgDir string, manifest *FilingManifest) error {
				path := filepath.Join(pkgDir, manifest.Artifacts[0].RelativePath)
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				_, err = f.Write([]byte{0x00, 0x00})
				return err
			},
			errMsg: "size mismatch",
		},
		{
			name: "Deleted artifact file from disk",
			tamper: func(pkgDir string, manifest *FilingManifest) error {
				path := filepath.Join(pkgDir, manifest.Artifacts[0].RelativePath)
				return os.Remove(path)
			},
			errMsg: "missing artifact file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			opts := BuildPackageOptions{
				Jurisdiction:     JurisdictionCalifornia,
				OrganizationID:   "org_tamper_test",
				OrganizationName: "Tamper Corp",
				RepositoryID:     "repo_ai_tamper",
				SignerName:       "Security Officer",
				SignerEmail:      "sec@corp.com",
			}

			manifest, err := builder.BuildPackage(opts)
			if err != nil {
				t.Fatalf("failed to build package: %v", err)
			}

			tempDir, err := os.MkdirTemp("", "airom-tamper-subtest-*")
			if err != nil {
				t.Fatalf("failed to create temp dir: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			if err := builder.ExportToDirectory(manifest, tempDir); err != nil {
				t.Fatalf("failed to export package: %v", err)
			}

			if err := tc.tamper(tempDir, manifest); err != nil {
				t.Fatalf("tampering setup failed: %v", err)
			}

			_, err = agent.VerifyPackage(tempDir)
			if err == nil {
				t.Fatalf("[%s] expected VerifyPackage to fail-closed on tampering, but it succeeded", tc.name)
			}
		})
	}
}

func TestQA_AdversarialStatePortalRejectionHandling(t *testing.T) {
	statusCodes := []int{
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	}

	for _, code := range statusCodes {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "State Portal Simulated Error", code)
		}))

		builder := NewPackageBuilder()
		agent := NewFilingAgent(server.Client())

		opts := BuildPackageOptions{
			Jurisdiction:     JurisdictionColorado,
			OrganizationID:   "org_err_test",
			OrganizationName: "Err Corp",
			RepositoryID:     "repo_err",
			SignerName:       "Signer",
			SignerEmail:      "signer@err.com",
		}

		manifest, _ := builder.BuildPackage(opts)
		receipt, err := agent.SubmitPackage(context.Background(), manifest, server.URL)
		server.Close()

		if err == nil {
			t.Errorf("expected error for HTTP %d response, got receipt: %+v", code, receipt)
		}
	}
}

func TestQA_AdversarialExtremeDatesAndLeapYears(t *testing.T) {
	engine := NewRenewalEngine()

	// Leap day filing
	leapDay := time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	now := leapDay.AddDate(0, 0, 100)

	history := FilingHistoryMap{
		JurisdictionColorado: leapDay,
	}
	mods := SubstantialModMap{}

	cal := engine.ComputeCalendar("org_leap", history, mods, now)
	if len(cal.Items) == 0 {
		t.Fatal("expected non-empty calendar for leap year filing")
	}

	// Verify urgency classifications across extreme boundary values
	urgencies := map[int]RenewalUrgency{
		-100: UrgencyOverdue,
		-1:   UrgencyOverdue,
		0:    UrgencyUrgent1D,
		1:    UrgencyUrgent1D,
		2:    UrgencyUpcoming7D,
		7:    UrgencyUpcoming7D,
		8:    UrgencyUpcoming14D,
		14:   UrgencyUpcoming14D,
		15:   UrgencyUpcoming30D,
		30:   UrgencyUpcoming30D,
		31:   UrgencyUpcoming90D,
		90:   UrgencyUpcoming90D,
		91:   UrgencyCurrent,
		1000: UrgencyCurrent,
	}

	for days, expected := range urgencies {
		got := ClassifyUrgency(days)
		if got != expected {
			t.Errorf("for %d days: expected urgency %s, got %s", days, expected, got)
		}
	}
}
