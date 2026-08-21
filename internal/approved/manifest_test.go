package approved

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadManifest_MissingFile(t *testing.T) {
	dir := t.TempDir()
	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if m != nil {
		t.Fatalf("expected nil manifest, got %+v", m)
	}
}

func TestLoadManifest_Valid(t *testing.T) {
	dir := t.TempDir()
	content := []byte(`schema_version: "1.0"
repo: "test-repo"
approved:
  - purl: "pkg:npm/react@18.0.0"
    reason: "Standard UI lib"
`)
	err := os.WriteFile(filepath.Join(dir, ".airomapproved"), content, 0644)
	if err != nil {
		t.Fatal(err)
	}

	m, err := LoadManifest(dir)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if m == nil {
		t.Fatal("expected manifest, got nil")
	}
	if len(m.Approved) != 1 {
		t.Fatalf("expected 1 approved component, got %d", len(m.Approved))
	}
	if m.Approved[0].PURL != "pkg:npm/react@18.0.0" {
		t.Errorf("unexpected purl %q", m.Approved[0].PURL)
	}
}

func TestIsApproved_Approved(t *testing.T) {
	m := &ApprovedManifest{
		Approved: []ComponentApproval{
			{PURL: "pkg:pypi/requests*", Scope: []string{"src/*"}},
		},
	}
	isApproved, status, _ := m.IsApproved("pkg:pypi/requests@2.28.1", "src/main.py")
	if !isApproved || status != "approved" {
		t.Errorf("expected approved, got %v, %s", isApproved, status)
	}
}

func TestIsApproved_ScopeMismatch(t *testing.T) {
	m := &ApprovedManifest{
		Approved: []ComponentApproval{
			{PURL: "pkg:pypi/requests*", Scope: []string{"src/*"}},
		},
	}
	isApproved, status, _ := m.IsApproved("pkg:pypi/requests@2.28.1", "test/test.py")
	if isApproved || status != "scope_mismatch" {
		t.Errorf("expected scope_mismatch, got %v, %s", isApproved, status)
	}
}

func TestIsApproved_Deny(t *testing.T) {
	m := &ApprovedManifest{
		Deny: []ComponentApproval{
			{PURL: "pkg:npm/evil*"},
		},
		Approved: []ComponentApproval{
			{PURL: "pkg:npm/evil*"}, // Deny should take precedence
		},
	}
	isApproved, status, _ := m.IsApproved("pkg:npm/evil@1.0.0", "src/main.js")
	if isApproved || status != "denied" {
		t.Errorf("expected denied, got %v, %s", isApproved, status)
	}
}

func TestIsApproved_Unapproved(t *testing.T) {
	m := &ApprovedManifest{
		Approved: []ComponentApproval{
			{PURL: "pkg:npm/good*"},
		},
	}
	isApproved, status, _ := m.IsApproved("pkg:npm/unknown@1.0.0", "src/main.js")
	if isApproved || status != "unapproved" {
		t.Errorf("expected unapproved, got %v, %s", isApproved, status)
	}
}

func TestSignature_Integrity(t *testing.T) {
	m := &ApprovedManifest{
		SchemaVersion: "1.0",
		Repo:          "test",
		Approved: []ComponentApproval{
			{PURL: "pkg:npm/test"},
		},
	}
	sig1 := ComputeSignature(m)
	if sig1 == "" {
		t.Fatal("expected non-empty signature")
	}

	m.Approved[0].PURL = "pkg:npm/test2"
	sig2 := ComputeSignature(m)
	if sig1 == sig2 {
		t.Fatal("expected different signatures for different content")
	}
}

func TestCheckConfigDrift(t *testing.T) {
	m := &ApprovedManifest{
		Approved: []ComponentApproval{
			{
				PURL: "pkg:npm/model*",
				PermittedConfig: map[string]string{
					"max_temp": "0.7",
					"max_tokens": "1000",
				},
			},
		},
	}

	tests := []struct {
		name       string
		purl       string
		params     map[string]string
		wantDrift  bool
		wantStatus string
	}{
		{
			name: "within limits",
			purl: "pkg:npm/model@1.0",
			params: map[string]string{
				"temperature": "0.5",
				"max_tokens": "500",
			},
			wantDrift: false,
		},
		{
			name: "temperature exceeded",
			purl: "pkg:npm/model@1.0",
			params: map[string]string{
				"temperature": "0.8",
			},
			wantDrift: true,
			wantStatus: "config_drift",
		},
		{
			name: "max_tokens exceeded",
			purl: "pkg:npm/model@1.0",
			params: map[string]string{
				"max_tokens": "1500",
			},
			wantDrift: true,
			wantStatus: "config_drift",
		},
		{
			name: "unrelated component",
			purl: "pkg:npm/other@1.0",
			params: map[string]string{
				"temperature": "0.8",
			},
			wantDrift: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			drift, status, _ := m.CheckConfigDrift(tt.purl, tt.params)
			if drift != tt.wantDrift {
				t.Errorf("CheckConfigDrift() drift = %v, want %v", drift, tt.wantDrift)
			}
			if drift && status != tt.wantStatus {
				t.Errorf("CheckConfigDrift() status = %v, want %v", status, tt.wantStatus)
			}
		})
	}
}

