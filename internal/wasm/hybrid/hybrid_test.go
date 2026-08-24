package hybrid

import (
	"context"
	"testing"

	"github.com/airomhq/airom/internal/wasm"
)

func TestHybridPipeline_FastPathSkipping(t *testing.T) {
	p := NewPipeline(nil)
	defer p.Close()

	nonAICode := []byte(`
package main
import "fmt"
func main() {
    fmt.Println("Hello Web Server on port 8080")
}
`)

	hasCandidates, calls, err := p.ScanFile(context.Background(), wasm.LangGo, nonAICode)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if hasCandidates {
		t.Errorf("expected zero candidate keywords for standard web server")
	}

	if len(calls) != 0 {
		t.Errorf("expected 0 calls, got %d", len(calls))
	}
}

func TestHybridPipeline_CandidateDetection(t *testing.T) {
	p := NewPipeline(nil)
	defer p.Close()

	aiCode := []byte(`
import openai
client = openai.OpenAI()
resp = client.chat.completions.create(model="gpt-4o", temperature=0.7)
`)

	hasCandidates, calls, err := p.ScanFile(context.Background(), wasm.LangPython, aiCode)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}

	if !hasCandidates {
		t.Fatalf("expected candidate keyword match")
	}

	if len(calls) == 0 {
		t.Fatalf("expected extracted calls, got 0")
	}

	if calls[0].Kwargs["model"] != "gpt-4o" || calls[0].Kwargs["temperature"] != "0.7" {
		t.Errorf("extracted kwargs mismatch: %+v", calls[0].Kwargs)
	}
}

func TestAccuracyOracle_Scoreboard(t *testing.T) {
	oracle := NewAccuracyOracle()

	// 90 true negatives skipped by fastpath
	for i := 0; i < 90; i++ {
		oracle.RecordObservation(false, false, false)
	}
	// 10 true positives evaluated by AST
	for i := 0; i < 10; i++ {
		oracle.RecordObservation(true, true, true)
	}

	sb := oracle.Scoreboard()
	if sb.Precision != 1.0 {
		t.Errorf("expected 1.0 precision, got %f", sb.Precision)
	}
	if sb.Recall != 1.0 {
		t.Errorf("expected 1.0 recall, got %f", sb.Recall)
	}
	if sb.F1Score != 1.0 {
		t.Errorf("expected 1.0 F1, got %f", sb.F1Score)
	}
	if sb.FastPathSkippedFiles != 90 {
		t.Errorf("expected 90 skipped files, got %d", sb.FastPathSkippedFiles)
	}

	t.Log(sb.FormatTable())
}
