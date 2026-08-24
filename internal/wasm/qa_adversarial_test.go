package wasm

import (
	"context"
	"strings"
	"sync"
	"testing"
)

func TestQA_AdversarialBytecodeAndCorruptStreams(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	corruptInputs := [][]byte{
		{0x00, 0x61, 0x73, 0x6d, 0x99, 0x99, 0x99, 0x99}, // Corrupted WASM magic
		[]byte("\x00\xff\xfe\xfd\x00\x00\x00"),           // Binary junk
		[]byte(strings.Repeat("(", 5000)),                // Unclosed open parens
		[]byte("def broken_syntax(:::"),                  // Syntax error
	}

	for i, input := range corruptInputs {
		_, _, metrics, err := engine.Execute(context.Background(), LangPython, input, func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
			// Mock parser that detects syntax anomaly
			if strings.Contains(string(code), "broken") || len(code) < 10 {
				return nil, nil, ErrInvalidBytecode
			}
			return &ASTNode{Type: "raw"}, nil, nil
		})

		// Must fail closed without panicking
		if input[0] == 0x00 && err == nil {
			t.Errorf("case %d expected error on corrupted binary, got nil (status=%s)", i, metrics.Status)
		}
	}
}

func TestQA_AdversarialDeepRecursionBomb(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())
	defer engine.Close()

	// Build a 1,000-deep nested expression
	var b strings.Builder
	for i := 0; i < 1000; i++ {
		b.WriteString("f(")
	}
	b.WriteString(`"gpt-4o"`)
	for i := 0; i < 1000; i++ {
		b.WriteString(")")
	}

	bomb := []byte(b.String())

	node, _, metrics, err := engine.Execute(context.Background(), LangPython, bomb, func(ctx context.Context, code []byte) (*ASTNode, []CallSite, error) {
		// Mock recursive tree builder with depth safety
		curr := &ASTNode{Type: "call", Text: "root"}
		for j := 0; j < 1000; j++ {
			child := &ASTNode{Type: "nested_call"}
			curr.Children = append(curr.Children, child)
			curr = child
		}
		return curr, nil, nil
	})

	if err != nil || metrics.Status != StatusSuccess || node == nil {
		t.Fatalf("failed to process recursion bomb safely: %v (status=%s)", err, metrics.Status)
	}
}

func TestQA_AdversarialConcurrentCloses(t *testing.T) {
	engine := NewEngine(DefaultSandboxConfig())

	var wg sync.WaitGroup
	wg.Add(10)

	// Close concurrently from multiple goroutines
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			_ = engine.Close()
		}()
	}

	wg.Wait()

	// New operations after close should fail cleanly
	_, _, metrics, err := engine.Execute(context.Background(), LangPython, []byte("code"), func(ctx context.Context, c []byte) (*ASTNode, []CallSite, error) {
		return &ASTNode{}, nil, nil
	})

	if err == nil {
		t.Fatalf("expected error executing on closed engine, got nil (status=%s)", metrics.Status)
	}
}
