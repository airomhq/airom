package embodied

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeEmbodiedScale_50KNodes(t *testing.T) {
	detector := NewDetector()

	const numNodes = 50000
	nodes := make([]EmbodiedNodeSpec, numNodes)
	for i := 0; i < numNodes; i++ {
		nodes[i] = EmbodiedNodeSpec{
			NodeName:        fmt.Sprintf("/robot_%d/policy_node", i),
			ROSDistribution: "humble",
			ActionModelName: "Octo-Base",
			ControlTopic:    "/arm/command",
			HasEStopBinding: true,
			HasSafetyClamp:  true,
			ActuatorLimits: ActuatorSafetyPolicy{
				MaxLinearVelocityMps: 1.0,
				MaxJointTorqueNm:     50.0,
				EmergencyStopTopic:   "/e_stop",
				SafetyStandard:       StandardISO13849,
				HeartbeatTimeoutMs:   100,
			},
		}
	}

	start := time.Now()
	for i := 0; i < numNodes; i++ {
		res := detector.EvaluateNode(nodes[i])
		if !res.Conformant {
			t.Fatalf("failed at iter %d", i)
		}
	}
	duration := time.Since(start)

	nodesPerSec := float64(numNodes) / duration.Seconds()
	t.Logf("=== SPRINT 91 SCALE: 50K EMBODIED AI ROBOTICS NODES EVALUATED ===")
	t.Logf("Nodes:      %d", numNodes)
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f nodes/sec", nodesPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentEmbodiedStorm_100Workers(t *testing.T) {
	detector := NewDetector()
	node := EmbodiedNodeSpec{
		NodeName:        "/conc_node",
		ROSDistribution: "jazzy",
		ActionModelName: "RT-2",
		HasEStopBinding: true,
		HasSafetyClamp:  true,
		ActuatorLimits: ActuatorSafetyPolicy{
			EmergencyStopTopic: "/e_stop",
			HeartbeatTimeoutMs: 50,
		},
	}

	const numWorkers = 100
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(numWorkers)
	errCh := make(chan error, numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				res := detector.EvaluateNode(node)
				if !res.Conformant {
					errCh <- fmt.Errorf("unexpected non-conformant verdict")
					return
				}
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrency error: %v", err)
	}

	totalOps := numWorkers * iterations
	duration := time.Since(start)
	t.Logf("=== SPRINT 91 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkEmbodied_EvaluateNode(b *testing.B) {
	detector := NewDetector()
	node := EmbodiedNodeSpec{
		NodeName:        "/bench_node",
		ROSDistribution: "humble",
		HasEStopBinding: true,
		HasSafetyClamp:  true,
		ActuatorLimits:  ActuatorSafetyPolicy{EmergencyStopTopic: "/e_stop", HeartbeatTimeoutMs: 50},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.EvaluateNode(node)
	}
}
