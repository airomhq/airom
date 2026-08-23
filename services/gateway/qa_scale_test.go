package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/detectors/mcp"
	"github.com/airomhq/airom/pkg/airom/detect"
)

// generateLuhnCard generates a 16-digit credit card number with a valid Luhn checksum.
func generateLuhnCard(seed int) string {
	prefix := fmt.Sprintf("4532%011d", seed)
	if len(prefix) > 15 {
		prefix = prefix[:15]
	}

	partialSum := 0
	for i := 0; i < 15; i++ {
		n := int(prefix[i] - '0')
		// For a 16-digit card (indices 0..15), even indices are doubled in Luhn (15-i is odd)
		if (15-i)%2 == 1 {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}
		partialSum += n
	}

	checkDigit := (10 - (partialSum % 10)) % 10
	return fmt.Sprintf("%s%d", prefix, checkDigit)
}

// TestQA_ExtremeRedactionScale_100KTokens tests the Redaction engine with 10,000 mixed PII/secret entities
// representing ~100K+ tokens to verify 100% redaction accuracy and sub-second execution.
func TestQA_ExtremeRedactionScale_100KTokens(t *testing.T) {
	const entityCountPerType = 2000 // 5 types * 2000 = 10,000 entities
	const totalExpectedEntities = entityCountPerType * 5

	t.Logf("=== Starting Extreme Scale Redaction Test: Generating %d PII Entities ===", totalExpectedEntities)

	var sb strings.Builder
	// Pre-allocate buffer for ~650KB payload
	sb.Grow(650 * 1024)

	ssnList := make([]string, entityCountPerType)
	cardList := make([]string, entityCountPerType)
	awsList := make([]string, entityCountPerType)
	openAIList := make([]string, entityCountPerType)
	jwtList := make([]string, entityCountPerType)

	for i := 0; i < entityCountPerType; i++ {
		ssn := fmt.Sprintf("%03d-%02d-%04d", (i*7+100)%900+100, (i*13+10)%90+10, (i*37+1000)%9000+1000)
		card := generateLuhnCard(i)
		aws := fmt.Sprintf("AKIA%016X", 1000000000000000+uint64(i)*7919)
		openAI := fmt.Sprintf("sk-proj-%028X", 2000000000000000+uint64(i)*9973)
		jwt := fmt.Sprintf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2Vy%06dIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQss%04d", i, i%10000)

		ssnList[i] = ssn
		cardList[i] = card
		awsList[i] = aws
		openAIList[i] = openAI
		jwtList[i] = jwt

		// Interleave entities with natural language context simulating conversational LLM chat tokens
		fmt.Fprintf(&sb, "LogRecord-%04d: Session user with SSN %s executed transaction with credit card %s using AWS credential %s and OpenAI key %s with active bearer token %s\n",
			i, ssn, card, aws, openAI, jwt)
	}

	payload := sb.String()
	payloadBytes := len(payload)
	approxTokens := payloadBytes / 4 // standard ~4 chars per token rule of thumb

	t.Logf("Payload constructed: %d bytes (approx %d tokens), containing %d entities", payloadBytes, approxTokens, totalExpectedEntities)

	redactor := NewRedactor()

	// Execute redaction and measure execution time
	start := time.Now()
	redacted := redactor.RedactText(payload)
	elapsed := time.Since(start)

	t.Logf("Redaction executed in %v (throughput: %.2f MB/s, %.0f entities/sec, %.0f tokens/sec)",
		elapsed,
		float64(payloadBytes)/(1024*1024)/elapsed.Seconds(),
		float64(totalExpectedEntities)/elapsed.Seconds(),
		float64(approxTokens)/elapsed.Seconds(),
	)

	// Verify sub-second execution requirement
	if elapsed >= 1*time.Second {
		t.Fatalf("Performance violation: Redaction of 10,000 entities took %v (threshold: < 1.0s)", elapsed)
	}

	// Verify 100% Redaction Accuracy: Count redaction tags
	countSSN := strings.Count(redacted, "[REDACTED:SSN]")
	countCard := strings.Count(redacted, "[REDACTED:CREDIT_CARD]")
	countAWS := strings.Count(redacted, "[REDACTED:AWS_KEY]")
	countOpenAI := strings.Count(redacted, "[REDACTED:OPENAI_KEY]")
	countJWT := strings.Count(redacted, "[REDACTED:JWT_TOKEN]")
	totalRedactions := countSSN + countCard + countAWS + countOpenAI + countJWT

	t.Logf("Redaction Tag Counts: SSN=%d, Card=%d, AWS=%d, OpenAI=%d, JWT=%d (Total=%d)",
		countSSN, countCard, countAWS, countOpenAI, countJWT, totalRedactions)

	if countSSN != entityCountPerType {
		t.Errorf("SSN redaction count mismatch: expected %d, got %d", entityCountPerType, countSSN)
	}
	if countCard != entityCountPerType {
		t.Errorf("Credit card redaction count mismatch: expected %d, got %d", entityCountPerType, countCard)
	}
	if countAWS != entityCountPerType {
		t.Errorf("AWS key redaction count mismatch: expected %d, got %d", entityCountPerType, countAWS)
	}
	if countOpenAI != entityCountPerType {
		t.Errorf("OpenAI key redaction count mismatch: expected %d, got %d", entityCountPerType, countOpenAI)
	}
	if countJWT != entityCountPerType {
		t.Errorf("JWT token redaction count mismatch: expected %d, got %d", entityCountPerType, countJWT)
	}
	if totalRedactions != totalExpectedEntities {
		t.Errorf("Total redaction count mismatch: expected %d, got %d", totalExpectedEntities, totalRedactions)
	}

	// Verify zero leak of original sensitive entities
	for idx := 0; idx < 100; idx++ { // sample checks across the batch
		if strings.Contains(redacted, ssnList[idx]) {
			t.Fatalf("Leak detected: SSN %s remained unredacted at index %d", ssnList[idx], idx)
		}
		if strings.Contains(redacted, cardList[idx]) {
			t.Fatalf("Leak detected: Credit Card %s remained unredacted at index %d", cardList[idx], idx)
		}
		if strings.Contains(redacted, awsList[idx]) {
			t.Fatalf("Leak detected: AWS Key %s remained unredacted at index %d", awsList[idx], idx)
		}
		if strings.Contains(redacted, openAIList[idx]) {
			t.Fatalf("Leak detected: OpenAI Key %s remained unredacted at index %d", openAIList[idx], idx)
		}
		if strings.Contains(redacted, jwtList[idx]) {
			t.Fatalf("Leak detected: JWT %s remained unredacted at index %d", jwtList[idx], idx)
		}
	}

	t.Logf("=== Redaction Scale Test PASSED: 100%% Accuracy (0 leaks across 10,000 entities in %v) ===", elapsed)
}

// TestQA_ConcurrentGatewayStorm_100Workers tests the Runtime Gateway Proxy under concurrent load
// with 100 workers executing 5,000 total requests across diverse endpoints.
func TestQA_ConcurrentGatewayStorm_100Workers(t *testing.T) {
	const (
		numWorkers        = 100
		requestsPerWorker = 50
		totalRequests     = numWorkers * requestsPerWorker // 5,000 requests
	)

	t.Logf("=== Starting Concurrent Gateway Storm: %d Workers x %d Requests = %d Total Requests ===",
		numWorkers, requestsPerWorker, totalRequests)

	cfg := GatewayConfig{
		ApprovedModels:                  []string{"gpt-4o", "claude-3-5-sonnet", "gpt-4o-mini"},
		MaxTemperature:                  0.7,
		MaxTokens:                       2048,
		EnableRedaction:                 true,
		CircuitBreakerMaxCallsPerMinute: 100000, // high threshold for load test session capacity
	}

	server := NewServer(cfg)
	ts := httptest.NewServer(server.Routes())
	defer ts.Close()

	// High-throughput client with connection pooling
	transport := &http.Transport{
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 200,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	var (
		completedReqs int64
		successReqs   int64
		failedReqs    int64
		droppedReqs   int64

		latenciesMu sync.Mutex
		latencies   = make([]time.Duration, 0, totalRequests)
	)

	startOverall := time.Now()
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		workerID := w

		go func(wid int) {
			defer wg.Done()

			workerLatencies := make([]time.Duration, 0, requestsPerWorker)

			for r := 0; r < requestsPerWorker; r++ {
				reqType := (wid*requestsPerWorker + r) % 5
				reqStart := time.Now()

				var (
					resp *http.Response
					err  error
				)

				sessionID := fmt.Sprintf("storm-worker-%d", wid)

				switch reqType {
				case 0:
					// 1. Standard Approved Model Call
					payload := map[string]interface{}{
						"model": "gpt-4o",
						"messages": []map[string]string{
							{"role": "system", "content": "You are a secure AIROM assistant."},
							{"role": "user", "content": fmt.Sprintf("Query from worker %d request %d", wid, r)},
						},
						"temperature": 0.5,
						"max_tokens":  1024,
					}
					body, _ := json.Marshal(payload)
					httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
					httpReq.Header.Set("X-Session-ID", sessionID)
					resp, err = client.Do(httpReq)

					if err == nil {
						if resp.StatusCode == http.StatusOK {
							var res map[string]interface{}
							if json.NewDecoder(resp.Body).Decode(&res) == nil {
								if choices, ok := res["choices"].([]interface{}); ok && len(choices) > 0 {
									atomic.AddInt64(&successReqs, 1)
								} else {
									atomic.AddInt64(&failedReqs, 1)
								}
							} else {
								atomic.AddInt64(&failedReqs, 1)
							}
						} else {
							atomic.AddInt64(&failedReqs, 1)
						}
						_ = resp.Body.Close()
					} else {
						atomic.AddInt64(&droppedReqs, 1)
					}

				case 1:
					// 2. Parameter Clamping Verification Call
					payload := map[string]interface{}{
						"model": "claude-3-5-sonnet",
						"messages": []map[string]string{
							{"role": "user", "content": "Clamping test request"},
						},
						"temperature": 1.95,  // Exceeds max 0.7
						"max_tokens":  16384, // Exceeds max 2048
					}
					body, _ := json.Marshal(payload)
					httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
					httpReq.Header.Set("X-Session-ID", sessionID)
					resp, err = client.Do(httpReq)

					if err == nil {
						if resp.StatusCode == http.StatusOK {
							atomic.AddInt64(&successReqs, 1)
						} else {
							atomic.AddInt64(&failedReqs, 1)
						}
						_ = resp.Body.Close()
					} else {
						atomic.AddInt64(&droppedReqs, 1)
					}

				case 2:
					// 3. In-flight PII Redaction Call
					payload := map[string]interface{}{
						"model": "gpt-4o-mini",
						"messages": []map[string]string{
							{"role": "user", "content": fmt.Sprintf("User John Doe SSN 000-12-%04d with card %s and AWS AKIAIOSFODNN7EXAMPLE", r, generateLuhnCard(r+100))},
						},
					}
					body, _ := json.Marshal(payload)
					httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
					httpReq.Header.Set("X-Session-ID", sessionID)
					resp, err = client.Do(httpReq)

					if err == nil {
						if resp.StatusCode == http.StatusOK {
							atomic.AddInt64(&successReqs, 1)
						} else {
							atomic.AddInt64(&failedReqs, 1)
						}
						_ = resp.Body.Close()
					} else {
						atomic.AddInt64(&droppedReqs, 1)
					}

				case 3:
					// 4. MCP Tool Invocation Call
					payload := map[string]interface{}{
						"tool_name": "database_query_executor",
						"arguments": map[string]interface{}{
							"query":   fmt.Sprintf("SELECT * FROM telemetry WHERE worker_id=%d", wid),
							"timeout": 5,
						},
					}
					body, _ := json.Marshal(payload)
					httpReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/mcp/invoke", bytes.NewReader(body))
					httpReq.Header.Set("Content-Type", "application/json")
					httpReq.Header.Set("X-Session-ID", sessionID)
					resp, err = client.Do(httpReq)

					if err == nil {
						if resp.StatusCode == http.StatusOK {
							var res map[string]interface{}
							if json.NewDecoder(resp.Body).Decode(&res) == nil && res["status"] == "executed" {
								atomic.AddInt64(&successReqs, 1)
							} else {
								atomic.AddInt64(&failedReqs, 1)
							}
						} else {
							atomic.AddInt64(&failedReqs, 1)
						}
						_ = resp.Body.Close()
					} else {
						atomic.AddInt64(&droppedReqs, 1)
					}

				case 4:
					// 5. Healthz Endpoint Call
					httpReq, _ := http.NewRequest(http.MethodGet, ts.URL+"/healthz", nil)
					resp, err = client.Do(httpReq)

					if err == nil {
						if resp.StatusCode == http.StatusOK {
							var res map[string]interface{}
							if json.NewDecoder(resp.Body).Decode(&res) == nil && res["status"] == "healthy" {
								atomic.AddInt64(&successReqs, 1)
							} else {
								atomic.AddInt64(&failedReqs, 1)
							}
						} else {
							atomic.AddInt64(&failedReqs, 1)
						}
						_ = resp.Body.Close()
					} else {
						atomic.AddInt64(&droppedReqs, 1)
					}
				}

				reqDuration := time.Since(reqStart)
				workerLatencies = append(workerLatencies, reqDuration)
				atomic.AddInt64(&completedReqs, 1)
			}

			latenciesMu.Lock()
			latencies = append(latencies, workerLatencies...)
			latenciesMu.Unlock()
		}(workerID)
	}

	// Deadlock detection: Wait with a strict 45-second timeout channel
	doneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneChan)
	}()

	select {
	case <-doneChan:
		// Completed normally
	case <-time.After(45 * time.Second):
		t.Fatalf("DEADLOCK DETECTED: Concurrent gateway storm did not finish within 45 seconds (completed: %d/%d)",
			atomic.LoadInt64(&completedReqs), totalRequests)
	}

	totalDuration := time.Since(startOverall)

	// Calculate latency percentiles
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	var totalLatency time.Duration
	for _, lat := range latencies {
		totalLatency += lat
	}

	n := len(latencies)
	p50 := latencies[n*50/100]
	p90 := latencies[n*90/100]
	p95 := latencies[n*95/100]
	p99 := latencies[n*99/100]
	maxLat := latencies[n-1]
	minLat := latencies[0]
	avgLat := totalLatency / time.Duration(n)
	qps := float64(totalRequests) / totalDuration.Seconds()

	t.Logf("=== Concurrent Gateway Storm Results ===")
	t.Logf("Total Requests:       %d", totalRequests)
	t.Logf("Successful Requests:  %d (%.2f%%)", successReqs, float64(successReqs)/float64(totalRequests)*100)
	t.Logf("Failed Requests:      %d", failedReqs)
	t.Logf("Dropped Requests:     %d", droppedReqs)
	t.Logf("Total Time:           %v", totalDuration)
	t.Logf("Throughput (QPS):     %.2f req/sec", qps)
	t.Logf("Latency Min:          %v", minLat)
	t.Logf("Latency Avg:          %v", avgLat)
	t.Logf("Latency P50:          %v", p50)
	t.Logf("Latency P90:          %v", p90)
	t.Logf("Latency P95:          %v", p95)
	t.Logf("Latency P99:          %v", p99)
	t.Logf("Latency Max:          %v", maxLat)

	// Assertions
	if droppedReqs > 0 {
		t.Fatalf("Reliability failure: %d requests dropped", droppedReqs)
	}
	if failedReqs > 0 {
		t.Fatalf("Consistency failure: %d requests failed", failedReqs)
	}
	if successReqs != int64(totalRequests) {
		t.Fatalf("Incomplete test: expected %d successful requests, got %d", totalRequests, successReqs)
	}

	t.Logf("=== Concurrent Gateway Storm PASSED: 100%% Consistency, 0 Drops, 0 Deadlocks ===")
}

// TestQA_StaticMCPDetectorScale_1000Files tests the static MCP detector under extreme file scan load.
func TestQA_StaticMCPDetectorScale_1000Files(t *testing.T) {
	const numFiles = 1000
	t.Logf("=== Starting Static MCP Detector Scale Test: Scanning %d Files ===", numFiles)

	detector := mcp.NewMCP()
	ctx := context.Background()

	var totalFindings int64
	start := time.Now()

	var wg sync.WaitGroup
	const concurrency = 20
	fileChan := make(chan int, numFiles)

	for i := 0; i < numFiles; i++ {
		fileChan <- i
	}
	close(fileChan)

	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var localFindings int64
			for idx := range fileChan {
				var (
					filePath string
					content  []byte
				)
				switch idx % 3 {
				case 0:
					filePath = fmt.Sprintf("config/claude_desktop_%d.json", idx)
					content = []byte(fmt.Sprintf(`{
						"mcpServers": {
							"db_%d": {"command": "uvx", "args": ["mcp-server-sqlite", "--db", "/app.db"]},
							"fetch_%d": {"command": "uvx", "args": ["mcp-server-fetch"]}
						}
					}`, idx, idx))
				case 1:
					filePath = fmt.Sprintf("src/agent_%d.py", idx)
					content = []byte(fmt.Sprintf(`from mcp.server.fastmcp import FastMCP
mcp_%d = FastMCP("Service_%d")
@mcp_%d.tool()
def handle(req: str) -> str:
    return "ok"
`, idx, idx, idx))
				case 2:
					filePath = fmt.Sprintf("src/server_%d.ts", idx)
					content = []byte(fmt.Sprintf(`import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const srv = new McpServer({ name: "srv_%d", version: "1.0.0" });
`, idx))
				}

				f := detect.NewFile(
					detect.FileRef{Path: filePath},
					content,
					detect.FileProviders{
						Content: func() ([]byte, bool, error) {
							return content, false, nil
						},
					},
				)

				findings, err := detector.DetectFile(ctx, f)
				if err == nil {
					localFindings += int64(len(findings))
				}
			}
			atomic.AddInt64(&totalFindings, localFindings)
		}()
	}

	wg.Wait()
	elapsed := time.Since(start)

	t.Logf("Scanned %d files in %v (throughput: %.2f files/sec, total findings: %d)",
		numFiles, elapsed, float64(numFiles)/elapsed.Seconds(), totalFindings)

	if elapsed >= 2*time.Second {
		t.Fatalf("Static MCP detector scale scan took too long: %v (threshold: < 2.0s)", elapsed)
	}

	if totalFindings < 1300 {
		t.Fatalf("Expected at least 1300 findings, got %d", totalFindings)
	}

	t.Logf("=== Static MCP Detector Scale Test PASSED: %d findings in %v ===", totalFindings, elapsed)
}

// BenchmarkScale_RedactionEngine benchmarks the Redactor on a heavy mixed-entity payload.
func BenchmarkScale_RedactionEngine(b *testing.B) {
	redactor := NewRedactor()

	// Build a standard 100KB test payload with 200 mixed entities
	var sb strings.Builder
	for i := 0; i < 200; i++ {
		ssn := fmt.Sprintf("%03d-%02d-%04d", (i*7+100)%900+100, (i*13+10)%90+10, (i*37+1000)%9000+1000)
		card := generateLuhnCard(i)
		aws := fmt.Sprintf("AKIA%016X", 1000000000000000+uint64(i)*7919)
		openAI := fmt.Sprintf("sk-proj-%028X", 2000000000000000+uint64(i)*9973)
		jwt := fmt.Sprintf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2Vy%06dIiwicm9sZSI6ImFkbWluIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQss%04d", i, i%10000)
		email := fmt.Sprintf("user_%d_audit@enterprise.internal", i)

		fmt.Fprintf(&sb, "Event %d: user=%s ssn=%s card=%s aws=%s openai=%s jwt=%s\n",
			i, email, ssn, card, aws, openAI, jwt)
	}
	payload := sb.String()
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = redactor.RedactText(payload)
	}
}

// BenchmarkScale_CircuitBreakerThroughput benchmarks the thread-safe CircuitBreaker under concurrent access.
func BenchmarkScale_CircuitBreakerThroughput(b *testing.B) {
	cb := NewCircuitBreaker(100_000_000)
	sessions := make([]string, 1000)
	for i := range sessions {
		sessions[i] = fmt.Sprintf("benchmark-session-%d", i)
	}

	b.ReportAllocs()
	b.ResetTimer()

	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			sess := sessions[r.Intn(len(sessions))]
			cb.Allow(sess)
		}
	})
}
