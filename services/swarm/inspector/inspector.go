package inspector

import (
	"strings"
	"sync"
	"time"
)

// Inspector monitors multi-agent collaboration graphs in real-time.
type Inspector struct {
	rootGoal string
	agents   map[string]*SwarmAgent
	messages []SwarmMessage
	mu       sync.RWMutex
}

// NewInspector constructs a swarm communication inspector.
func NewInspector(rootGoal string) *Inspector {
	return &Inspector{
		rootGoal: rootGoal,
		agents:   make(map[string]*SwarmAgent),
	}
}

// RegisterAgent adds an active agent node to the swarm topology.
func (ins *Inspector) RegisterAgent(agent SwarmAgent) {
	ins.mu.Lock()
	defer ins.mu.Unlock()
	ins.agents[agent.ID] = &agent
}

// RecordMessage records an inter-agent delegation or communication event.
func (ins *Inspector) RecordMessage(msg SwarmMessage) {
	ins.mu.Lock()
	defer ins.mu.Unlock()

	msg.Timestamp = time.Now().UTC()
	msg.DriftScore = calculateGoalDrift(ins.rootGoal, msg.Intent+" "+msg.Payload)

	ins.messages = append(ins.messages, msg)

	if sender, ok := ins.agents[msg.SenderID]; ok {
		sender.TotalHops++
	}
}

// GetTopology compiles the current swarm communication graph and drift statistics.
func (ins *Inspector) GetTopology() SwarmTopology {
	ins.mu.RLock()
	defer ins.mu.RUnlock()

	topo := SwarmTopology{
		RootGoal:    ins.rootGoal,
		Agents:      make(map[string]*SwarmAgent),
		Messages:    ins.messages,
		InspectedAt: time.Now().UTC(),
	}

	for k, v := range ins.agents {
		copyAgent := *v
		topo.Agents[k] = &copyAgent
		if copyAgent.TotalHops > topo.MaxHopsReached {
			topo.MaxHopsReached = copyAgent.TotalHops
		}
	}

	if len(ins.messages) > 0 {
		var totalDrift float64
		for _, m := range ins.messages {
			totalDrift += m.DriftScore
		}
		topo.AverageDrift = totalDrift / float64(len(ins.messages))
	}

	return topo
}

func calculateGoalDrift(rootGoal, text string) float64 {
	rootWords := strings.Fields(strings.ToLower(rootGoal))
	textWords := strings.Fields(strings.ToLower(text))

	if len(rootWords) == 0 || len(textWords) == 0 {
		return 0.0
	}

	rootSet := make(map[string]bool)
	for _, w := range rootWords {
		rootSet[w] = true
	}

	matches := 0
	for _, w := range textWords {
		if rootSet[w] {
			matches++
		}
	}

	// Jaccard similarity approximation
	similarity := float64(matches) / float64(len(rootWords)+len(textWords)-matches)
	drift := 1.0 - similarity
	if drift < 0.0 {
		drift = 0.0
	}
	if drift > 1.0 {
		drift = 1.0
	}
	return drift
}
