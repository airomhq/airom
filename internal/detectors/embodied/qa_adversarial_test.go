package embodied

import (
	"strings"
	"testing"
)

func TestQA_AdversarialExtremeTorqueAndVelocity(t *testing.T) {
	detector := NewDetector()

	extremeNode := EmbodiedNodeSpec{
		NodeName:        "/extreme_power_arm",
		ROSDistribution: "humble",
		HasEStopBinding: true,
		HasSafetyClamp:  true,
		ActuatorLimits: ActuatorSafetyPolicy{
			MaxLinearVelocityMps: 9999.99,  // Super-sonic velocity
			MaxJointTorqueNm:     100000.0, // Mega-torque
			EmergencyStopTopic:   "/e_stop",
			HeartbeatTimeoutMs:   50,
		},
	}

	res := detector.EvaluateNode(extremeNode)
	if res.Conformant || len(res.Violations) < 2 {
		t.Fatalf("expected extreme velocity and torque to trigger safety violations")
	}
}

func TestQA_AdversarialCorruptedNodeNames(t *testing.T) {
	detector := NewDetector()

	maliciousNode := EmbodiedNodeSpec{
		NodeName:        "../../../dev/null; rm -rf /; #\x00\xff",
		ROSDistribution: "humble",
		ActionModelName: "AdversarialModel<script>",
	}

	res := detector.EvaluateNode(maliciousNode)
	if res.Component == nil {
		t.Fatalf("expected component returned even on corrupted node name")
	}

	if strings.Contains(string(res.Component.ID), " ") || strings.Contains(string(res.Component.ID), ";") {
		t.Errorf("component ID was not properly sanitized: %s", res.Component.ID)
	}
}
