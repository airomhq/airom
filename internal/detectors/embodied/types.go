// Package embodied provides discovery and safety evaluation for embodied AI,
// ROS/ROS2 robotics nodes, kinematics policies, and physical actuator safety envelopes.
package embodied

import (
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

// SafetyStandard identifies the robotics safety norm.
type SafetyStandard string

const (
	StandardISO13849 SafetyStandard = "ISO_13849_PL_d" // Functional safety of machinery
	StandardISO10218 SafetyStandard = "ISO_10218"      // Robots and robotic devices safety
	StandardUL4600   SafetyStandard = "UL_4600"        // Autonomous products safety evaluation
)

// ActuatorSafetyPolicy defines physical hardware velocity, force, and emergency-stop constraints.
type ActuatorSafetyPolicy struct {
	MaxLinearVelocityMps  float64        `json:"maxLinearVelocityMps"`  // Maximum allowed m/s (e.g. 1.5)
	MaxAngularVelocityRps float64        `json:"maxAngularVelocityRps"` // Maximum allowed rad/s (e.g. 2.0)
	MaxJointTorqueNm      float64        `json:"maxJointTorqueNm"`      // Maximum joint torque (e.g. 50.0 Nm)
	EmergencyStopTopic    string         `json:"emergencyStopTopic"`    // e.g. "/safety/e_stop"
	SafetyStandard        SafetyStandard `json:"safetyStandard"`
	HeartbeatTimeoutMs    int            `json:"heartbeatTimeoutMs"` // e.g. 100ms
}

// EmbodiedNodeSpec represents a discovered robotics perception/action AI model node.
type EmbodiedNodeSpec struct {
	NodeName        string               `json:"nodeName"`        // e.g. "/vision_policy_node"
	ROSDistribution string               `json:"rosDistribution"` // e.g. "humble", "iron", "jazzy"
	ActionModelName string               `json:"actionModelName"` // e.g. "RT-2", "Octo-Base", "OpenVLA"
	ControlTopic    string               `json:"controlTopic"`    // e.g. "/arm_controller/command"
	ActuatorLimits  ActuatorSafetyPolicy `json:"actuatorLimits"`
	HasEStopBinding bool                 `json:"hasEStopBinding"`
	HasSafetyClamp  bool                 `json:"hasSafetyClamp"`
	SourceLocation  string               `json:"sourceLocation"`
}

// SafetyEvaluationResult contains the safety verdict for an embodied AI node.
type SafetyEvaluationResult struct {
	NodeName    string           `json:"nodeName"`
	Conformant  bool             `json:"conformant"`
	Violations  []string         `json:"violations"`
	Component   *airom.Component `json:"component"`
	EvaluatedAt time.Time        `json:"evaluatedAt"`
}
