package sovereign

import (
	"strings"
	"testing"
)

func TestQA_AdversarialTinyAndNegativeDimensions(t *testing.T) {
	renderer := NewRenderer()
	state := TerminalState{ActiveView: ViewDashboard}

	frame := renderer.RenderFrame(state, 0, 0)
	if !strings.Contains(frame, "AIROM SOVEREIGN") {
		t.Errorf("expected fallback render on zero dimensions")
	}

	frameNegative := renderer.RenderFrame(state, -50, -50)
	if !strings.Contains(frameNegative, "AIROM SOVEREIGN") {
		t.Errorf("expected fallback render on negative dimensions")
	}
}

func TestQA_AdversarialUnknownViewMode(t *testing.T) {
	renderer := NewRenderer()
	state := TerminalState{ActiveView: "UNKNOWN_VIEW_MODE"}

	frame := renderer.RenderFrame(state, 80, 24)
	if !strings.Contains(frame, "Unknown View") {
		t.Errorf("expected unknown view fallback")
	}
}
