package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/airomhq/airom/internal/approved"
)

func TestApproveCmd(t *testing.T) {
	tmpDir := t.TempDir()

	// Init fake git repo
	err := os.Mkdir(filepath.Join(tmpDir, ".git"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	oldWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(oldWd) }()

	// Test approve execution
	t.Run("first approval", func(t *testing.T) {
		cmd := newApproveCmd()
		cmd.SetArgs([]string{"pkg:pypi/openai", "--scope", "src/**", "--max-temp", "0.7", "--ticket", "AI-123"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)

		err := cmd.ExecuteContext(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !strings.Contains(out.String(), "Approved component pkg:pypi/openai") {
			t.Errorf("unexpected output: %s", out.String())
		}

		manifest, err := approved.LoadManifest(tmpDir)
		if err != nil || manifest == nil {
			t.Fatalf("failed to load manifest: %v", err)
		}

		if len(manifest.Approved) != 1 {
			t.Fatalf("expected 1 approval, got %d", len(manifest.Approved))
		}

		app := manifest.Approved[0]
		if app.PURL != "pkg:pypi/openai" || len(app.Scope) == 0 || app.Scope[0] != "src/**" {
			t.Errorf("unexpected approval values: %+v", app)
		}
		if app.Ticket != "AI-123" {
			t.Errorf("unexpected ticket: %s", app.Ticket)
		}
		if app.PermittedConfig["max_temp"] != "0.7" {
			t.Errorf("unexpected max_temp: %s", app.PermittedConfig["max_temp"])
		}
	})

	t.Run("idempotency", func(t *testing.T) {
		cmd := newApproveCmd()
		cmd.SetArgs([]string{"pkg:pypi/openai", "--ticket", "AI-999"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)

		err := cmd.ExecuteContext(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		manifest, _ := approved.LoadManifest(tmpDir)
		if len(manifest.Approved) != 1 {
			t.Fatalf("expected 1 approval, got %d", len(manifest.Approved))
		}

		app := manifest.Approved[0]
		// It should overwrite ticket
		if app.Ticket != "AI-999" {
			t.Errorf("expected ticket to be updated to AI-999, got %s", app.Ticket)
		}
	})

	t.Run("revoke execution", func(t *testing.T) {
		cmd := newRevokeCmd()
		cmd.SetArgs([]string{"pkg:pypi/openai", "--reason", "deprecated"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)

		err := cmd.ExecuteContext(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		manifest, _ := approved.LoadManifest(tmpDir)
		if len(manifest.Approved) != 0 {
			t.Errorf("expected 0 approvals, got %d", len(manifest.Approved))
		}
		if len(manifest.Revocations) != 1 {
			t.Fatalf("expected 1 revocation, got %d", len(manifest.Revocations))
		}

		rev := manifest.Revocations[0]
		if rev.Reason != "deprecated" {
			t.Errorf("unexpected revocation reason: %s", rev.Reason)
		}
	})
}
