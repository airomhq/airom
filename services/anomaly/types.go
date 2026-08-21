package anomaly

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

type ParamDelta struct {
	OldValue string `json:"oldValue"`
	NewValue string `json:"newValue"`
}

type ComponentDelta struct {
	ComponentID  string                `json:"componentId"`
	PURL         string                `json:"purl"`
	OldVersion   string                `json:"oldVersion"`
	NewVersion   string                `json:"newVersion"`
	OldProvider  string                `json:"oldProvider"`
	NewProvider  string                `json:"newProvider"`
	ParamDeltas  map[string]ParamDelta `json:"paramDeltas"`
}

type DiffReport struct {
	BaseCommit string             `json:"baseCommit"`
	HeadCommit string             `json:"headCommit"`
	Added      []airom.Component  `json:"added"`
	Removed    []airom.Component  `json:"removed"`
	Modified   []ComponentDelta   `json:"modified"`
}

type Anomaly struct {
	ID          string `json:"id"`
	Type        string `json:"type"` // shadow-ai, model-swap, config-drift, proximity-hiring, proximity-credit, proximity-healthcare
	Severity    string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW
	Component   string `json:"component"`
	Location    string `json:"location"`
	Message     string `json:"message"`
	StatuteRef  string `json:"statuteRef"`
	Remediation string `json:"remediation"`
}

type AnomalyReport struct {
	Clean           bool          `json:"clean"`
	HighestSeverity string        `json:"highestSeverity"`
	Anomalies       []Anomaly     `json:"anomalies"`
	Diff            DiffReport    `json:"diff"`
	EvaluatedAt     time.Time     `json:"evaluatedAt"`
}
