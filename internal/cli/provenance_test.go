package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI_Provenance_Attest_Verify_Tree(t *testing.T) {
	bi := BuildInfo{Version: "1.0.0", Commit: "provenancecommit", Date: "2026-08-23"}

	// 1. Test `airom provenance attest`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{
		"provenance", "attest",
		"--model", "enterprise/finance-gpt",
		"--name", "Finance GPT",
		"--version", "2.1.0",
		"--base", "meta-llama/Llama-3-8B",
		"--license", "Apache-2.0",
	})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("provenance attest failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "Generated and Cryptographically Signed Model Provenance Attestation") {
		t.Errorf("expected attestation success banner, got: %s", outStr)
	}
	if !strings.Contains(outStr, "SLSA_BUILD_LEVEL_3") {
		t.Errorf("expected SLSA Level 3 in output, got: %s", outStr)
	}

	// 2. Test `airom provenance attest --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{
		"provenance", "attest",
		"--model", "enterprise/finance-gpt",
		"--json",
	})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("provenance attest --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "https://in-toto.io/Statement/v1") {
		t.Errorf("expected in-toto statement JSON, got: %s", outStr)
	}

	// 3. Test `airom provenance verify`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{
		"provenance", "verify",
		"--model", "enterprise/finance-gpt",
	})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("provenance verify failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "AI Model Provenance & Supply Chain Integrity VERIFIED") {
		t.Errorf("expected verification success, got: %s", outStr)
	}

	// 4. Test `airom provenance tree`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{
		"provenance", "tree",
		"--model", "enterprise/finance-gpt",
	})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("provenance tree failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, "AIROM MODEL SUPPLY CHAIN PROVENANCE") {
		t.Errorf("expected tree header banner, got: %s", outStr)
	}
	if !strings.Contains(outStr, "Llama-3-8B-Base") {
		t.Errorf("expected base model in tree, got: %s", outStr)
	}
}
