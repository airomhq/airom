// Package inspector implements multi-agent swarm topology discovery and communication inspection
// (ARCHITECTURE.md §16).
package inspector

import (
	"time"
)

// AgentProtocol classifies the orchestration framework governing the agent swarm.
type AgentProtocol string

const (
	ProtocolLangGraph   AgentProtocol = "langgraph"
	ProtocolCrewAI      AgentProtocol = "crewai"
	ProtocolAutoGen     AgentProtocol = "autogen"
	ProtocolOpenAISwarm AgentProtocol = "openai_swarm"
	ProtocolCustomA2A   AgentProtocol = "custom_agent_to_agent"
)

// SwarmAgent represents an autonomous agent participating in a collaborative swarm.
type SwarmAgent struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Role        string        `json:"role"`
	Framework   AgentProtocol `json:"framework"`
	ParentAgent string        `json:"parentAgent,omitempty"` // For hierarchical delegation
	ActiveTools []string      `json:"activeTools"`
	TotalHops   int           `json:"totalHops"`
}

// SwarmMessage represents an inter-agent message or tool delegation event.
type SwarmMessage struct {
	MessageID  string        `json:"messageId"`
	SenderID   string        `json:"senderId"`
	ReceiverID string        `json:"receiverId"`
	Framework  AgentProtocol `json:"framework"`
	Intent     string        `json:"intent"`
	Payload    string        `json:"payload"`
	DriftScore float64       `json:"driftScore"` // 0.0 - 1.0 (drift from root root-goal)
	Timestamp  time.Time     `json:"timestamp"`
}

// SwarmTopology captures the active directed communication graph of the agent swarm.
type SwarmTopology struct {
	RootGoal       string                 `json:"rootGoal"`
	Agents         map[string]*SwarmAgent `json:"agents"`
	Messages       []SwarmMessage         `json:"messages"`
	MaxHopsReached int                    `json:"maxHopsReached"`
	AverageDrift   float64                `json:"averageDrift"`
	InspectedAt    time.Time              `json:"inspectedAt"`
}
