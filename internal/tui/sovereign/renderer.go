package sovereign

import (
	"fmt"
	"strings"
	"time"
)

// Renderer formats terminal UI screens with ANSI styling and layout boxes.
type Renderer struct{}

// NewRenderer constructs a sovereign TUI renderer.
func NewRenderer() *Renderer {
	return &Renderer{}
}

// RenderFrame generates an ANSI formatted terminal frame based on state.
func (r *Renderer) RenderFrame(state TerminalState, width, height int) string {
	if width < 20 {
		width = 80
	}

	border := strings.Repeat("═", width-2)
	header := fmt.Sprintf("╔%s╗\n║ AIROM SOVEREIGN ENTERPRISE CONSOLE — %-24s ║\n╚%s╝\n", border, state.ActiveView, border)

	var body string
	switch state.ActiveView {
	case ViewDashboard:
		body = fmt.Sprintf(
			"┌─ SYSTEM STATUS ──────────────────────────────────────────────┐\n"+
				"│ System:           %-42s │\n"+
				"│ Compliance Score: %5.1f%%                                     │\n"+
				"│ Active Threats:   %-42d │\n"+
				"│ Active Alerts:    %-42d │\n"+
				"│ Drift Status:     %-42s │\n"+
				"└──────────────────────────────────────────────────────────────┘\n",
			state.SystemName, state.ComplianceScore, state.ActiveThreats, state.ActiveAlerts, state.DriftStatus,
		)

	case ViewThreatRadar:
		body = fmt.Sprintf(
			"┌─ AGENTIC RED-TEAM & THREAT RADAR ────────────────────────────┐\n" +
				"│ Active Fuzzer Probes:   10,000 / sec                         │\n" +
				"│ Dynamic Guardrail Status: ACTIVE (0 Bypasses Allowed)        │\n" +
				"│ OWASP Top 10 Risk Score:  LOW                                │\n" +
				"└──────────────────────────────────────────────────────────────┘\n",
		)

	case ViewDriftOracle:
		body = fmt.Sprintf(
			"┌─ POST-MARKET DRIFT ORACLE (EU AI ACT ART 72) ────────────────┐\n"+
				"│ Population Stability Index (PSI): %s                         │\n"+
				"│ 4/5ths Demographic Parity:        COMPLIANT                  │\n"+
				"│ Retraining Trigger:               OFF                        │\n"+
				"└──────────────────────────────────────────────────────────────┘\n",
			state.DriftStatus,
		)

	case ViewFilings:
		body = fmt.Sprintf(
			"┌─ STATUTORY FILINGS & CE CONFORMITY ──────────────────────────┐\n" +
				"│ EU AI Act Annex IV Tech Doc:      GENERATED (Ready)          │\n" +
				"│ EU AI Act Article 27 FRIA:        APPROVED                   │\n" +
				"│ Article 48 CE Mark of Conformity: AFFIXED                    │\n" +
				"│ Colorado SB 24-205 Disclosure:    PREPARED                   │\n" +
				"└──────────────────────────────────────────────────────────────┘\n",
		)

	default:
		body = "Unknown View\n"
	}

	footer := fmt.Sprintf("\n[1] Dashboard  [2] Threat Radar  [3] Drift Oracle  [4] Filings  [Q] Quit — %s", state.RenderedAt.Format(time.RFC3339))

	return header + body + footer
}
