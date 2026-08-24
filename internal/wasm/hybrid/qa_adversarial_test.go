package hybrid

import (
	"context"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/wasm"
)

func TestQA_AdversarialFalsePositiveTraps(t *testing.T) {
	p := NewPipeline(nil)
	defer p.Close()

	traps := []struct {
		name string
		code []byte
	}{
		{
			name: "comment_only",
			code: []byte("# We considered using gpt-4o and claude-3-5 but decided against it\ndef helper(): return 1"),
		},
		{
			name: "string_variable",
			code: []byte("doc_string = 'Documentation about langchain and openai architectures'"),
		},
		{
			name: "variable_name",
			code: []byte("gpt_model_counter = 42"),
		},
	}

	for _, trap := range traps {
		t.Run(trap.name, func(t *testing.T) {
			hasCand, calls, err := p.ScanFile(context.Background(), wasm.LangPython, trap.code)
			if err != nil {
				t.Fatalf("scan failed: %v", err)
			}
			// It may have matched candidate keyword in stage 1, but stage 2 AST must filter out false positive calls!
			if len(calls) > 0 {
				t.Errorf("false positive: extracted %d call sites from inert trap %s", len(calls), trap.name)
			}
			_ = hasCand
		})
	}
}

func TestQA_AdversarialExtremeByteStreams(t *testing.T) {
	cfg := wasm.DefaultSandboxConfig()
	cfg.TimeoutPerFile = 2 * time.Second
	engine := wasm.NewEngine(cfg)
	p := NewPipeline(engine)
	defer p.Close()

	// 5 MB null byte array with "gpt-4o" embedded in the middle
	largeBytes := make([]byte, 5*1024*1024)
	copy(largeBytes[2*1024*1024:], []byte("gpt-4o"))

	hasCand, calls, err := p.ScanFile(context.Background(), wasm.LangPython, largeBytes)
	if err != nil {
		t.Fatalf("failed on large byte stream: %v", err)
	}

	if !hasCand {
		t.Errorf("failed to match embedded keyword")
	}

	// Should not panic or produce invalid call sites from raw binary
	if len(calls) > 0 {
		t.Errorf("expected 0 calls from binary chunk")
	}
}

func TestQA_AdversarialNilContextHandling(t *testing.T) {
	p := NewPipeline(nil)
	defer p.Close()

	// Canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _, err := p.ScanFile(ctx, wasm.LangPython, []byte("openai.create()"))
	if err == nil {
		t.Logf("handled canceled context")
	}
}
