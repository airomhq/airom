package inspector

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeSwarmScale_50KMessages(t *testing.T) {
	ins := NewInspector("Enterprise compliance audit and scanning")

	for i := 0; i < 100; i++ {
		ins.RegisterAgent(SwarmAgent{ID: fmt.Sprintf("agent-%d", i), Framework: ProtocolLangGraph})
	}

	const numMessages = 50000
	start := time.Now()

	for i := 0; i < numMessages; i++ {
		ins.RecordMessage(SwarmMessage{
			MessageID:  fmt.Sprintf("msg-%d", i),
			SenderID:   fmt.Sprintf("agent-%d", i%100),
			ReceiverID: fmt.Sprintf("agent-%d", (i+1)%100),
			Intent:     "Audit statutory requirements for compliance",
			Payload:    "Executing test inspection",
		})
	}
	duration := time.Since(start)

	topo := ins.GetTopology()
	if len(topo.Messages) != numMessages {
		t.Fatalf("expected %d messages in topology", numMessages)
	}

	msgsPerSec := float64(numMessages) / duration.Seconds()
	t.Logf("=== SPRINT 64 SCALE: 50K INTER-AGENT SWARM MESSAGES INSPECTED ===")
	t.Logf("Messages:    %d", numMessages)
	t.Logf("Avg Drift:   %f", topo.AverageDrift)
	t.Logf("Latency:     %v", duration)
	t.Logf("Throughput:  %.2f msgs/sec", msgsPerSec)

	if duration > 1*time.Second {
		t.Errorf("expected execution < 1s, took %v", duration)
	}
}

func TestQA_ConcurrentSwarmStorm_100Workers(t *testing.T) {
	ins := NewInspector("Coordinate distributed AI workloads")
	const numWorkers = 100
	const iterations = 500

	for i := 0; i < numWorkers; i++ {
		ins.RegisterAgent(SwarmAgent{ID: fmt.Sprintf("agent-%d", i), Framework: ProtocolCrewAI})
	}

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	start := time.Now()
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			defer wg.Done()
			senderID := fmt.Sprintf("agent-%d", workerID)
			receiverID := fmt.Sprintf("agent-%d", (workerID+1)%numWorkers)
			for j := 0; j < iterations; j++ {
				ins.RecordMessage(SwarmMessage{
					MessageID:  fmt.Sprintf("msg-%d-%d", workerID, j),
					SenderID:   senderID,
					ReceiverID: receiverID,
					Intent:     "Subtask dispatch",
					Payload:    "Run scan",
				})
			}
		}(i)
	}

	wg.Wait()

	topo := ins.GetTopology()
	totalOps := numWorkers * iterations
	duration := time.Since(start)

	if len(topo.Messages) != totalOps {
		t.Fatalf("expected %d messages, got %d", totalOps, len(topo.Messages))
	}

	t.Logf("=== SPRINT 64 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:   %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkSwarm_RecordMessage(b *testing.B) {
	ins := NewInspector("Root Goal Benchmark")
	ins.RegisterAgent(SwarmAgent{ID: "a1"})
	ins.RegisterAgent(SwarmAgent{ID: "a2"})

	msg := SwarmMessage{
		MessageID:  "b",
		SenderID:   "a1",
		ReceiverID: "a2",
		Intent:     "Benchmark test message",
		Payload:    "Payload content",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ins.RecordMessage(msg)
	}
}
