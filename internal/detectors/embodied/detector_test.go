package embodied

import (
	"testing"
)

func TestEmbodied_SafeNodeConforms(t *testing.T) {
	detector := NewDetector()

	node := EmbodiedNodeSpec{
		NodeName:        "/arm_policy_controller",
		ROSDistribution: "humble",
		ActionModelName: "OpenVLA-7B",
		ControlTopic:    "/joint_trajectory_controller/command",
		HasEStopBinding: true,
		HasSafetyClamp:  true,
		ActuatorLimits: ActuatorSafetyPolicy{
			MaxLinearVelocityMps:  1.0,
			MaxAngularVelocityRps: 1.5,
			MaxJointTorqueNm:      40.0,
			EmergencyStopTopic:    "/safety/hardware_e_stop",
			SafetyStandard:        StandardISO13849,
			HeartbeatTimeoutMs:    50,
		},
	}

	res := detector.EvaluateNode(node)
	if !res.Conformant || len(res.Violations) != 0 {
		t.Fatalf("expected conformant node, got violations: %+v", res.Violations)
	}

	if res.Component == nil || res.Component.Name != "OpenVLA-7B" {
		t.Errorf("unexpected component generated: %+v", res.Component)
	}
}

func TestEmbodied_UnsafeNodeFails(t *testing.T) {
	detector := NewDetector()

	unsafeNode := EmbodiedNodeSpec{
		NodeName:        "/unconstrained_actuator_node",
		ROSDistribution: "humble",
		ActionModelName: "RT-2-Raw",
		ControlTopic:    "/direct_motor_pwm",
		HasEStopBinding: false, // Missing E-Stop
		HasSafetyClamp:  false, // Missing Safety Clamp
	}

	res := detector.EvaluateNode(unsafeNode)
	if res.Conformant || len(res.Violations) < 2 {
		t.Fatalf("expected unsafe node to fail with at least 2 critical violations")
	}
}
