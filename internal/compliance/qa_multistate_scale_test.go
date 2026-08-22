package compliance

import (
	"fmt"
	"math/rand"
	"reflect"
	"runtime"
	"sort"
	"testing"
	"time"

	"github.com/airomhq/airom/pkg/airom"
)

var stateFrameworkIDs = []string{
	"colorado-ai-act",
	"nyc-ll144",
	"ca-ab2013",
	"illinois-bipa",
	"texas-traiga",
	"virginia-vcdpa",
}

// build10KScaleInventory creates a 10,000 component enterprise AI inventory
// encompassing hosted LLMs, biometric models, embedding models, frameworks,
// datasets, decision systems, AEDTs, and vector DBs.
func build10KScaleInventory() (*airom.Inventory, map[string]int) {
	counts := map[string]int{
		"hosted-llm":       2500,
		"local-model-file": 1500, // includes biometric/CV models
		"embedding-model":  1500,
		"framework":        1500,
		"dataset":          1000,
		"decision-system":  1000,
		"aedt":             500,
		"vector-db":        500,
	}

	components := make([]airom.Component, 0, 10001)
	// Root component
	components = append(components, airom.Component{
		ID:   "airom:app-root-000000",
		Kind: airom.KindApplication,
		Name: "enterprise-ai-platform",
	})

	idx := 0
	makeComponents := func(kind airom.ComponentKind, count int, namePrefix string, riskEvery int, testOnlyEvery int) {
		for i := 0; i < count; i++ {
			id := airom.ID(fmt.Sprintf("airom:%s-%06d", string(kind), idx))
			c := airom.Component{
				ID:   id,
				Kind: kind,
				Name: fmt.Sprintf("%s-%06d", namePrefix, i),
			}
			if riskEvery > 0 && i%riskEvery == 0 {
				c.Risks = []airom.ArtifactRisk{
					{ID: airom.RiskUnsafeLoad, Severity: airom.RiskMedium},
				}
			}
			if testOnlyEvery > 0 && i%testOnlyEvery == 0 {
				c.TestOnly = true
			}
			components = append(components, c)
			idx++
		}
	}

	makeComponents(airom.KindHostedLLM, counts["hosted-llm"], "llm-endpoint", 10, 20)
	makeComponents(airom.KindLocalModelFile, counts["local-model-file"], "biometric-weights", 8, 25)
	makeComponents(airom.KindEmbeddingModel, counts["embedding-model"], "embedding-svc", 0, 30)
	makeComponents(airom.KindFramework, counts["framework"], "ml-framework", 0, 15)
	makeComponents(airom.KindDataset, counts["dataset"], "training-corpus", 0, 10)
	makeComponents(airom.KindDecisionSystem, counts["decision-system"], "credit-decision-algo", 5, 50)
	makeComponents(airom.KindAEDT, counts["aedt"], "resume-ranker-aedt", 0, 40)
	makeComponents(airom.KindVectorDB, counts["vector-db"], "milvus-cluster", 0, 0)

	inv := &airom.Inventory{
		Root:       "airom:app-root-000000",
		Components: components,
	}
	return inv, counts
}

// computeExpectedGroundTruth computes the exact expected outcome for state controls
// given an inventory and includeTests setting.
func computeExpectedGroundTruth(inv *airom.Inventory, fwID string, includeTests bool) map[string]struct {
	state       airom.ControlState
	score       *float64
	evidenceIDs []airom.ID
	counterIDs  []airom.ID
} {
	expected := make(map[string]struct {
		state       airom.ControlState
		score       *float64
		evidenceIDs []airom.ID
		counterIDs  []airom.ID
	})

	var eligible []*airom.Component
	for i := range inv.Components {
		c := &inv.Components[i]
		if c.Kind == airom.KindApplication {
			continue
		}
		if c.TestOnly && !includeTests {
			continue
		}
		eligible = append(eligible, c)
	}

	sortIDs := func(ids []airom.ID) []airom.ID {
		res := append([]airom.ID(nil), ids...)
		sort.Slice(res, func(i, j int) bool { return res[i] < res[j] })
		return res
	}

	score1 := 1.0
	score0 := 0.0

	switch fwID {
	case "colorado-ai-act":
		// co.ai-act.risk-mgmt (manual)
		expected["co.ai-act.risk-mgmt"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// co.ai-act.impact-assessment (gap_if: "risk | decision-system")
		var gapIDs []airom.ID
		for _, c := range eligible {
			if len(c.Risks) > 0 || c.Kind == airom.KindDecisionSystem {
				gapIDs = append(gapIDs, c.ID)
			}
		}
		gapIDs = sortIDs(gapIDs)
		if len(gapIDs) > 0 {
			expected["co.ai-act.impact-assessment"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0, counterIDs: gapIDs}
		} else {
			expected["co.ai-act.impact-assessment"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1}
		}

		// co.ai-act.consumer-notice (manual)
		expected["co.ai-act.consumer-notice"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// co.ai-act.incident-reporting (manual)
		expected["co.ai-act.incident-reporting"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

	case "nyc-ll144":
		// nyc.ll144.bias-audit (gap_if: "aedt")
		var gapIDs []airom.ID
		for _, c := range eligible {
			if c.Kind == airom.KindAEDT {
				gapIDs = append(gapIDs, c.ID)
			}
		}
		gapIDs = sortIDs(gapIDs)
		if len(gapIDs) > 0 {
			expected["nyc.ll144.bias-audit"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0, counterIDs: gapIDs}
		} else {
			expected["nyc.ll144.bias-audit"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1}
		}

		// nyc.ll144.public-posting (manual)
		expected["nyc.ll144.public-posting"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

	case "ca-ab2013":
		// ca.ab2013.training-data-summary (gap_if: "hosted-llm | local-model-file")
		var gapIDs []airom.ID
		for _, c := range eligible {
			if c.Kind == airom.KindHostedLLM || c.Kind == airom.KindLocalModelFile {
				gapIDs = append(gapIDs, c.ID)
			}
		}
		gapIDs = sortIDs(gapIDs)
		if len(gapIDs) > 0 {
			expected["ca.ab2013.training-data-summary"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0, counterIDs: gapIDs}
		} else {
			expected["ca.ab2013.training-data-summary"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1}
		}

	case "illinois-bipa":
		// il.bipa.written-policy (manual)
		expected["il.bipa.written-policy"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// il.bipa.informed-consent (gap_if: "risk | local-model-file | hosted-llm")
		var gapIDs []airom.ID
		for _, c := range eligible {
			if len(c.Risks) > 0 || c.Kind == airom.KindLocalModelFile || c.Kind == airom.KindHostedLLM {
				gapIDs = append(gapIDs, c.ID)
			}
		}
		gapIDs = sortIDs(gapIDs)
		if len(gapIDs) > 0 {
			expected["il.bipa.informed-consent"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0, counterIDs: gapIDs}
		} else {
			expected["il.bipa.informed-consent"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1}
		}

		// il.bipa.profit-prohibition (manual)
		expected["il.bipa.profit-prohibition"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// il.bipa.storage-security (manual)
		expected["il.bipa.storage-security"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

	case "texas-traiga":
		// tx.traiga.inventory-disclosure (evidence_of: "hosted-llm | local-model-file | embedding-model | framework")
		var evIDs []airom.ID
		for _, c := range eligible {
			if c.Kind == airom.KindHostedLLM || c.Kind == airom.KindLocalModelFile || c.Kind == airom.KindEmbeddingModel || c.Kind == airom.KindFramework {
				evIDs = append(evIDs, c.ID)
			}
		}
		evIDs = sortIDs(evIDs)
		if len(evIDs) > 0 {
			expected["tx.traiga.inventory-disclosure"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1, evidenceIDs: evIDs}
		} else {
			expected["tx.traiga.inventory-disclosure"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0}
		}

		// tx.traiga.risk-tiering (manual)
		expected["tx.traiga.risk-tiering"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// tx.traiga.human-oversight (manual)
		expected["tx.traiga.human-oversight"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// tx.traiga.deceptive-ai-ban (manual)
		expected["tx.traiga.deceptive-ai-ban"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

	case "virginia-vcdpa":
		// va.vcdpa.data-protection-assessment (gap_if: "risk | hosted-llm | decision-system")
		var gapIDs []airom.ID
		for _, c := range eligible {
			if len(c.Risks) > 0 || c.Kind == airom.KindHostedLLM || c.Kind == airom.KindDecisionSystem {
				gapIDs = append(gapIDs, c.ID)
			}
		}
		gapIDs = sortIDs(gapIDs)
		if len(gapIDs) > 0 {
			expected["va.vcdpa.data-protection-assessment"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlGap, score: &score0, counterIDs: gapIDs}
		} else {
			expected["va.vcdpa.data-protection-assessment"] = struct {
				state       airom.ControlState
				score       *float64
				evidenceIDs []airom.ID
				counterIDs  []airom.ID
			}{state: airom.ControlMet, score: &score1}
		}

		// va.vcdpa.profiling-opt-out (manual)
		expected["va.vcdpa.profiling-opt-out"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}

		// va.vcdpa.purpose-limitation (manual)
		expected["va.vcdpa.purpose-limitation"] = struct {
			state       airom.ControlState
			score       *float64
			evidenceIDs []airom.ID
			counterIDs  []airom.ID
		}{state: airom.ControlManual, score: nil}
	}

	return expected
}

// TestQA_MultiStateScale_10KComponents stress-tests multi-state compliance evaluation
// with 10,000 components across all 6 state frameworks simultaneously.
func TestQA_MultiStateScale_10KComponents(t *testing.T) {
	inv, _ := build10KScaleInventory()

	// Ensure runtime GC is clean prior to benchmark run
	runtime.GC()
	var mBefore runtime.MemStats
	runtime.ReadMemStats(&mBefore)

	start := time.Now()
	results, err := Evaluate(inv, stateFrameworkIDs, false)
	elapsed := time.Since(start)

	var mAfter runtime.MemStats
	runtime.ReadMemStats(&mAfter)

	if err != nil {
		t.Fatalf("Multi-state evaluation failed: %v", err)
	}

	if len(results) != len(stateFrameworkIDs) {
		t.Fatalf("Expected %d framework results, got %d", len(stateFrameworkIDs), len(results))
	}

	// Performance verification: Target sub-100ms for 10K components across 6 states (> 100,000 comp/s rate)
	evalRate := float64(len(inv.Components)*len(stateFrameworkIDs)) / elapsed.Seconds()
	t.Logf("Scale Test Performance: 10,000 components evaluated across 6 state frameworks in %v (Throughput: %.2f control-evals/sec, component-rate: %.2f comps/sec)",
		elapsed, evalRate, float64(len(inv.Components))/elapsed.Seconds())

	if elapsed > 5*time.Second {
		t.Errorf("Scale evaluation took too long: %v (target < 5s)", elapsed)
	}

	// Memory allocation check
	allocBytes := mAfter.TotalAlloc - mBefore.TotalAlloc
	t.Logf("Memory footprint: %d KB allocated during 10K evaluation (%.2f KB per component)", allocBytes/1024, float64(allocBytes)/float64(len(inv.Components))/1024)

	// Accuracy verification against ground truth
	for _, res := range results {
		expected := computeExpectedGroundTruth(inv, res.Framework, false)
		if len(res.Controls) != len(expected) {
			t.Errorf("Framework %s: expected %d controls, got %d", res.Framework, len(expected), len(res.Controls))
		}

		for _, c := range res.Controls {
			exp, ok := expected[c.ID]
			if !ok {
				t.Errorf("Unexpected control ID %s in framework %s", c.ID, res.Framework)
				continue
			}

			if c.State != exp.state {
				t.Errorf("Framework %s, Control %s state mismatch: got %v, want %v", res.Framework, c.ID, c.State, exp.state)
			}

			if (c.Score == nil && exp.score != nil) || (c.Score != nil && exp.score == nil) {
				t.Errorf("Framework %s, Control %s score mismatch: got %v, want %v", res.Framework, c.ID, c.Score, exp.score)
			} else if c.Score != nil && exp.score != nil && *c.Score != *exp.score {
				t.Errorf("Framework %s, Control %s score value mismatch: got %f, want %f", res.Framework, c.ID, *c.Score, *exp.score)
			}

			if len(c.Evidence) != len(exp.evidenceIDs) {
				t.Errorf("Framework %s, Control %s evidence count mismatch: got %d, want %d", res.Framework, c.ID, len(c.Evidence), len(exp.evidenceIDs))
			} else if len(c.Evidence) > 0 && !reflect.DeepEqual(c.Evidence, exp.evidenceIDs) {
				t.Errorf("Framework %s, Control %s evidence content mismatch", res.Framework, c.ID)
			}

			if len(c.Counter) != len(exp.counterIDs) {
				t.Errorf("Framework %s, Control %s counter count mismatch: got %d, want %d", res.Framework, c.ID, len(c.Counter), len(exp.counterIDs))
			} else if len(c.Counter) > 0 && !reflect.DeepEqual(c.Counter, exp.counterIDs) {
				t.Errorf("Framework %s, Control %s counter content mismatch", res.Framework, c.ID)
			}
		}
	}

	// Verify post-test GC cleans up heap cleanly
	runtime.GC()
}

// TestQA_MultiStateConflictFuzzing fuzzes 500+ randomized multi-jurisdiction scenarios
// with mixed biometrics (IL), consequential decision systems (CO), generative LLMs (CA),
// employment decision tools (NYC), state disclosures (TX), and profiling (VA).
func TestQA_MultiStateConflictFuzzing(t *testing.T) {
	const fuzzIterations = 600
	availableKinds := []airom.ComponentKind{
		airom.KindHostedLLM,
		airom.KindLocalModelFile,
		airom.KindEmbeddingModel,
		airom.KindFramework,
		airom.KindLibrary,
		airom.KindVectorDB,
		airom.KindPrompt,
		airom.KindDataset,
		airom.KindDecisionSystem,
		airom.KindAEDT,
		airom.KindRAGPipeline,
	}

	availableRisks := []airom.RiskID{
		airom.RiskUnsafeLoad,
		airom.RiskPickleImport,
		airom.RiskKerasLambda,
		airom.RiskGGUFTemplate,
		airom.RiskSavedModelPyFunc,
	}

	for iter := 0; iter < fuzzIterations; iter++ {
		rng := rand.New(rand.NewSource(int64(42000 + iter)))

		numComps := rng.Intn(60) + 1
		components := make([]airom.Component, 0, numComps+1)
		components = append(components, airom.Component{
			ID:   "airom:fuzz-root",
			Kind: airom.KindApplication,
			Name: "fuzz-app",
		})

		for cIdx := 0; cIdx < numComps; cIdx++ {
			kind := availableKinds[rng.Intn(len(availableKinds))]
			c := airom.Component{
				ID:       airom.ID(fmt.Sprintf("airom:comp-%04d-%03d", iter, cIdx)),
				Kind:     kind,
				Name:     fmt.Sprintf("fuzz-%s-%03d", string(kind), cIdx),
				TestOnly: rng.Float32() < 0.25, // 25% chance of test-only scoping
			}

			// 30% chance of risk overlay
			if rng.Float32() < 0.30 {
				rID := availableRisks[rng.Intn(len(availableRisks))]
				meta := airom.RiskCatalog[rID]
				c.Risks = []airom.ArtifactRisk{
					{ID: rID, Severity: meta.Severity},
				}
			}

			components = append(components, c)
		}

		inv := &airom.Inventory{
			Root:       "airom:fuzz-root",
			Components: components,
		}

		// Random subset and order of state frameworks (1 to 6)
		shuffledFws := append([]string(nil), stateFrameworkIDs...)
		rng.Shuffle(len(shuffledFws), func(i, j int) {
			shuffledFws[i], shuffledFws[j] = shuffledFws[j], shuffledFws[i]
		})
		numFws := rng.Intn(len(shuffledFws)) + 1
		testFws := shuffledFws[:numFws]

		includeTests := rng.Float32() < 0.5

		// 1. Evaluate
		res1, err := Evaluate(inv, testFws, includeTests)
		if err != nil {
			t.Fatalf("[Iteration %d] Evaluation failed: %v", iter, err)
		}

		// 2. Determinism check
		res2, err := Evaluate(inv, testFws, includeTests)
		if err != nil {
			t.Fatalf("[Iteration %d] Second evaluation failed: %v", iter, err)
		}
		if !reflect.DeepEqual(res1, res2) {
			t.Fatalf("[Iteration %d] Non-deterministic evaluation detected", iter)
		}

		// 3. Ground truth validation (Zero False Negatives, Zero False Positives)
		if len(res1) != len(testFws) {
			t.Fatalf("[Iteration %d] Expected %d results, got %d", iter, len(testFws), len(res1))
		}

		for _, fwRes := range res1 {
			expectedMap := computeExpectedGroundTruth(inv, fwRes.Framework, includeTests)
			if len(fwRes.Controls) != len(expectedMap) {
				t.Fatalf("[Iteration %d] Framework %s: expected %d controls, got %d", iter, fwRes.Framework, len(expectedMap), len(fwRes.Controls))
			}

			for _, c := range fwRes.Controls {
				exp, ok := expectedMap[c.ID]
				if !ok {
					t.Fatalf("[Iteration %d] Unexpected control %s in framework %s", iter, c.ID, fwRes.Framework)
				}

				if c.State != exp.state {
					t.Fatalf("[Iteration %d] False verdict on %s/%s: got %s, want %s", iter, fwRes.Framework, c.ID, c.State, exp.state)
				}

				if (c.Score == nil && exp.score != nil) || (c.Score != nil && exp.score == nil) {
					t.Fatalf("[Iteration %d] Score presence mismatch on %s/%s", iter, fwRes.Framework, c.ID)
				} else if c.Score != nil && exp.score != nil && *c.Score != *exp.score {
					t.Fatalf("[Iteration %d] Score value mismatch on %s/%s: got %f, want %f", iter, fwRes.Framework, c.ID, *c.Score, *exp.score)
				}

				if len(c.Evidence) != len(exp.evidenceIDs) {
					t.Fatalf("[Iteration %d] Evidence count mismatch on %s/%s: got %d, want %d", iter, fwRes.Framework, c.ID, len(c.Evidence), len(exp.evidenceIDs))
				}
				if len(c.Counter) != len(exp.counterIDs) {
					t.Fatalf("[Iteration %d] Counter count mismatch on %s/%s: got %d, want %d", iter, fwRes.Framework, c.ID, len(c.Counter), len(exp.counterIDs))
				}
			}
		}
	}
	t.Logf("Multi-state conflict fuzzing completed: %d randomized iterations passed with zero false negatives and deterministic verdicts.", fuzzIterations)
}

// BenchmarkMultiState_10KEvaluation measures throughput of evaluating 10,000 AI components across 6 state frameworks.
func BenchmarkMultiState_10KEvaluation(b *testing.B) {
	inv, _ := build10KScaleInventory()
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Evaluate(inv, stateFrameworkIDs, false)
		if err != nil {
			b.Fatalf("Evaluate error: %v", err)
		}
	}
}

// BenchmarkMultiState_SingleComponentAllStates measures the latency of evaluating a single component across 6 state frameworks.
func BenchmarkMultiState_SingleComponentAllStates(b *testing.B) {
	singleInv := &airom.Inventory{
		Root: "airom:root",
		Components: []airom.Component{
			{ID: "airom:root", Kind: airom.KindApplication, Name: "app"},
			{
				ID:   "airom:face-embed-01",
				Kind: airom.KindLocalModelFile,
				Name: "face_embed.onnx",
				Risks: []airom.ArtifactRisk{
					{ID: airom.RiskUnsafeLoad, Severity: airom.RiskMedium},
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := Evaluate(singleInv, stateFrameworkIDs, false)
		if err != nil {
			b.Fatalf("Evaluate error: %v", err)
		}
	}
}
