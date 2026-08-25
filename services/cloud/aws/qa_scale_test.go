package aws

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestQA_ExtremeAWSScale_50KEndpoints(t *testing.T) {
	connector := NewConnector()

	const numEndpoints = 50000
	sagemaker := make([]SageMakerEndpointSpec, numEndpoints)
	for i := 0; i < numEndpoints; i++ {
		sagemaker[i] = SageMakerEndpointSpec{
			EndpointARN:        fmt.Sprintf("arn:aws:sagemaker:us-east-1:123456789012:endpoint/ep-%d", i),
			EndpointName:       fmt.Sprintf("endpoint-%d", i),
			EndpointStatus:     "InService",
			InstanceType:       "ml.g5.xlarge",
			ModelArtifactS3URI: fmt.Sprintf("s3://models-bucket/model-%d.tar.gz", i),
			CreatedAt:          time.Now().UTC(),
		}
	}

	start := time.Now()
	res := connector.CompileAIBOM("123456789012", "us-east-1", nil, sagemaker)
	duration := time.Since(start)

	if res == nil || res.Inventory == nil {
		t.Fatalf("failed compilation")
	}

	epsPerSec := float64(numEndpoints) / duration.Seconds()
	t.Logf("=== SPRINT 76 SCALE: 50K AWS AI ENDPOINTS COMPILED ===")
	t.Logf("Endpoints:  %d", numEndpoints)
	t.Logf("Components: %d", len(res.Inventory.Components))
	t.Logf("Latency:    %v", duration)
	t.Logf("Throughput: %.2f endpoints/sec", epsPerSec)

	if duration > 5*time.Second {
		t.Errorf("expected execution < 5s, took %v", duration)
	}
}

func TestQA_ConcurrentAWSStorm_100Workers(t *testing.T) {
	connector := NewConnector()

	bedrock := []BedrockModelSpec{
		{ModelID: "anthropic.claude-3-haiku", ModelName: "Claude 3 Haiku", ProviderName: "Anthropic", Region: "us-east-1"},
	}
	sagemaker := []SageMakerEndpointSpec{
		{EndpointName: "sm-llm-1", InstanceType: "ml.g5.2xlarge", ModelArtifactS3URI: "s3://models/m.tar.gz"},
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
				res := connector.CompileAIBOM("123456789012", "us-east-1", bedrock, sagemaker)
				if res == nil || len(res.Inventory.Components) != 3 {
					errCh <- fmt.Errorf("worker %d iter %d invalid components count", workerID, j)
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
	t.Logf("=== SPRINT 76 CONCURRENCY: %d workers x %d iters ===", numWorkers, iterations)
	t.Logf("Completed:  %d ops in %v (%.2f ops/sec)", totalOps, duration, float64(totalOps)/duration.Seconds())
}

func BenchmarkAWS_CompileAIBOM(b *testing.B) {
	connector := NewConnector()
	bedrock := []BedrockModelSpec{{ModelID: "amazon.titan-text", ModelName: "Titan Text", ProviderName: "Amazon"}}
	sagemaker := []SageMakerEndpointSpec{{EndpointName: "titan-ep", ModelArtifactS3URI: "s3://models/titan.tar.gz"}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = connector.CompileAIBOM("123456789012", "us-east-1", bedrock, sagemaker)
	}
}
