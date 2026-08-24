package wasm

import (
	"context"
	"testing"
	"time"
)

func TestWASM_BasicExecution(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	source := []byte(`client.chat.completions.create(model="gpt-4o", temperature=0.7)`)

	node, calls, metrics, err := engine.Execute(context.Background(), LangPython, source, func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
		root := &ASTNode{
			Type:      "call_expression",
			Text:      string(code),
			StartLine: 1,
			EndLine:   1,
		}
		extractedCalls := []CallSite{
			{
				Function: "create",
				Receiver: "client.chat.completions",
				Kwargs: map[string]string{
					"model":       "gpt-4o",
					"temperature": "0.7",
				},
				LineNumber: 1,
			},
		}
		return root, extractedCalls, nil
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if metrics.Status != StatusSuccess {
		t.Errorf("expected status %s, got %s", StatusSuccess, metrics.Status)
	}

	if node == nil || len(calls) != 1 {
		t.Fatalf("expected 1 call site, got %d", len(calls))
	}

	if calls[0].Kwargs["model"] != "gpt-4o" || calls[0].Kwargs["temperature"] != "0.7" {
		t.Errorf("kwargs mismatch: %+v", calls[0].Kwargs)
	}
}

func TestWASM_MemoryCeilingEnforcement(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.MaxMemoryBytes = 1024 // 1 KB limit
	engine := NewEngine(cfg)
	defer engine.Close()

	oversized := make([]byte, 2048) // 2 KB payload

	_, _, metrics, err := engine.Execute(context.Background(), LangPython, oversized, func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
		return &ASTNode{}, nil, nil
	})

	if err != ErrMemoryExceeded {
		t.Fatalf("expected ErrMemoryExceeded, got %v", err)
	}

	if metrics.Status != StatusMemoryExceeded {
		t.Errorf("expected status %s, got %s", StatusMemoryExceeded, metrics.Status)
	}
}

func TestWASM_TimeoutEnforcement(t *testing.T) {
	cfg := DefaultSandboxConfig()
	cfg.TimeoutPerFile = 20 * time.Millisecond
	engine := NewEngine(cfg)
	defer engine.Close()

	_, _, metrics, err := engine.Execute(context.Background(), LangPython, []byte("loop"), func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
		time.Sleep(100 * time.Millisecond) // Exceed 20ms
		return &ASTNode{}, nil, nil
	})

	if err != ErrTimeout {
		t.Fatalf("expected ErrTimeout, got %v", err)
	}

	if metrics.Status != StatusTimeout {
		t.Errorf("expected status %s, got %s", StatusTimeout, metrics.Status)
	}
}

func TestWASM_TrapRecovery(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	_, _, metrics, err := engine.Execute(context.Background(), LangPython, []byte("panic"), func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
		panic("simulated WASM memory fault / SIGSEGV")
	})

	if err == nil {
		t.Fatalf("expected error from panic recovery, got nil")
	}

	if metrics.Status != StatusTrapped {
		t.Errorf("expected status %s, got %s", StatusTrapped, metrics.Status)
	}
}
