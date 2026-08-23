package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestCLI_Cluster(t *testing.T) {
	bi := BuildInfo{Version: "1.0.0", Commit: "clustercommit", Date: "2026-08-23"}

	// 1. Test `airom cluster status`
	root := newRootCmd(bi)
	var outBuf bytes.Buffer
	root.SetOut(&outBuf)
	root.SetArgs([]string{"cluster", "status"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("cluster status command failed: %v", err)
	}

	outStr := outBuf.String()
	if !strings.Contains(outStr, "AIROM HIGH-AVAILABILITY CLUSTER TOPOLOGY") {
		t.Errorf("expected cluster header banner, got: %s", outStr)
	}
	if !strings.Contains(outStr, "airom-node-us-east-1a") {
		t.Errorf("expected node in topology, got: %s", outStr)
	}

	// 2. Test `airom cluster status --json`
	root = newRootCmd(bi)
	outBuf.Reset()
	root.SetOut(&outBuf)
	root.SetArgs([]string{"cluster", "status", "--json"})

	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("cluster status --json failed: %v", err)
	}

	outStr = outBuf.String()
	if !strings.Contains(outStr, `"cluster_id": "airom-production-ha-cluster"`) {
		t.Errorf("expected cluster JSON output, got: %s", outStr)
	}
}
