package sovereign

import (
	"strings"
	"testing"
	"time"
)

func TestTUI_RenderDashboardView(t *testing.T) {
	renderer := NewRenderer()

	state := TerminalState{
		ActiveView:      ViewDashboard,
		SystemName:      "Enterprise-AI-Platform",
		ComplianceScore: 98.5,
		ActiveAlerts:    0,
		ActiveThreats:   0,
		DriftStatus:     "STABLE",
		RenderedAt:      time.Now().UTC(),
	}

	frame := renderer.RenderFrame(state, 80, 24)
	if !strings.Contains(frame, "AIROM SOVEREIGN ENTERPRISE CONSOLE") {
		t.Errorf("missing header in rendered frame")
	}

	if !strings.Contains(frame, "98.5%") || !strings.Contains(frame, "Enterprise-AI-Platform") {
		t.Errorf("missing system name or score in frame: %s", frame)
	}
}

func TestTUI_RenderAllViewModes(t *testing.T) {
	renderer := NewRenderer()

	views := []ViewMode{ViewThreatRadar, ViewDriftOracle, ViewFilings}
	for _, v := range views {
		state := TerminalState{
			ActiveView:  v,
			DriftStatus: "PSI: 0.02 (Negligible)",
			RenderedAt:  time.Now().UTC(),
		}
		frame := renderer.RenderFrame(state, 80, 24)
		if len(frame) < 100 {
			t.Errorf("frame too short for view %s", v)
		}
	}
}
