package embodied

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// Detector discovers and evaluates robotics embodied AI drivers and actuator safety envelopes.
type Detector struct {
	mu sync.RWMutex
}

// NewDetector constructs a new embodied AI detector.
func NewDetector() *Detector {
	return &Detector{}
}

// EvaluateNode analyzes an embodied node specification against ISO 13849/10218 safety envelopes.
func (d *Detector) EvaluateNode(node EmbodiedNodeSpec) SafetyEvaluationResult {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := time.Now().UTC()
	var violations []string

	// 1. Verify Emergency-Stop binding
	if !node.HasEStopBinding || node.ActuatorLimits.EmergencyStopTopic == "" {
		violations = append(violations, "CRITICAL: Node lacks active hardware Emergency-Stop (/e_stop) subscription (violates ISO 13849-1 PL d)")
	}

	// 2. Verify Velocity and Torque Clamp
	if !node.HasSafetyClamp {
		violations = append(violations, "HIGH: Node lacks software-level safety velocity and torque clamping (violates ISO 10218-1)")
	} else {
		if node.ActuatorLimits.MaxLinearVelocityMps > 2.0 {
			violations = append(violations, fmt.Sprintf("HIGH: Max linear velocity (%.2f m/s) exceeds collaborative robot safety ceiling of 2.0 m/s", node.ActuatorLimits.MaxLinearVelocityMps))
		}
		if node.ActuatorLimits.MaxJointTorqueNm > 150.0 {
			violations = append(violations, fmt.Sprintf("HIGH: Max joint torque (%.2f Nm) exceeds human-collaborative threshold of 150.0 Nm", node.ActuatorLimits.MaxJointTorqueNm))
		}
	}

	// 3. Heartbeat watchdog
	if node.ActuatorLimits.HeartbeatTimeoutMs <= 0 || node.ActuatorLimits.HeartbeatTimeoutMs > 250 {
		violations = append(violations, "MEDIUM: Actuator watchdog timeout missing or exceeds maximum 250ms latency ceiling")
	}

	cleanID := sanitizeID(fmt.Sprintf("ros2-embodied-%s-%s", node.ROSDistribution, node.NodeName))
	comp := airom.Component{
		ID:         airom.ID(cleanID),
		Kind:       airom.KindHostedLLM,
		Name:       node.ActionModelName,
		Provider:   airom.KnownString("Embodied-Robotics-AI"),
		Confidence: 1.0,
		PURL:       fmt.Sprintf("pkg:ros2/%s/%s@%s", node.ROSDistribution, strings.TrimPrefix(node.NodeName, "/"), node.ActionModelName),
		Props: []airom.KV{
			{Name: "embodied.node_name", Value: node.NodeName},
			{Name: "embodied.control_topic", Value: node.ControlTopic},
			{Name: "embodied.ros_distro", Value: node.ROSDistribution},
			{Name: "embodied.e_stop_topic", Value: node.ActuatorLimits.EmergencyStopTopic},
			{Name: "embodied.safety_standard", Value: string(node.ActuatorLimits.SafetyStandard)},
		},
	}

	return SafetyEvaluationResult{
		NodeName:    node.NodeName,
		Conformant:  len(violations) == 0,
		Violations:  violations,
		Component:   &comp,
		EvaluatedAt: now,
	}
}

func sanitizeID(raw string) string {
	h := sha256.Sum256([]byte(raw))
	short := hex.EncodeToString(h[:4])
	clean := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.ToLower(raw))
	if len(clean) > 40 {
		clean = clean[:40]
	}
	return fmt.Sprintf("%s-%s", clean, short)
}
