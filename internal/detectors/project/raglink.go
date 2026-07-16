package project

import (
	"context"

	"github.com/Roro1727/airom/pkg/airom"
	"github.com/Roro1727/airom/pkg/airom/detect"
)

// RAGLink synthesizes a rag-pipeline composite from phase-1 findings alone —
// no file reads. When the scan surfaced BOTH an embedding model and a vector
// database it stitches them into one rag-pipeline component with EMBEDS_WITH
// and CONTAINS edges (§17). It is best-effort and conservative: absent either
// half, it emits nothing.
type RAGLink struct{}

// NewRAGLink returns the RAG-composite ProjectDetector.
func NewRAGLink() *RAGLink { return &RAGLink{} }

// ID is the stable detector identity (SARIF ruleId).
func (*RAGLink) ID() string { return "project/raglink" }

// Version participates in cache keys; bump on any behavior change.
func (*RAGLink) Version() int { return 1 }

// Selector is ignored for project detectors — they pull via the Resolver.
func (*RAGLink) Selector() detect.Selector { return detect.Selector{} }

// DetectProject emits a single rag-pipeline finding when the prior view holds
// at least one embedding-model finding and one vector-db finding, anchored at
// the embedding finding's location.
func (rl *RAGLink) DetectProject(_ context.Context, _ detect.Resolver, prior *detect.FindingsView) ([]detect.Finding, error) {
	if prior == nil {
		return nil, nil
	}
	embeds := prior.ByKind(airom.KindEmbeddingModel)
	vdbs := prior.ByKind(airom.KindVectorDB)
	if len(embeds) == 0 || len(vdbs) == 0 {
		return nil, nil
	}
	emb := embeds[0]
	vdb := vdbs[0]

	f := detect.Finding{
		Claim: detect.ComponentClaim{
			Kind: airom.KindRAGPipeline,
			Name: "rag-pipeline",
		},
		Occurrence: airom.Occurrence{
			Location:   emb.Occurrence.Location, // representative anchor
			DetectorID: rl.ID(),
			Method:     airom.MethodSourceCode,
			Confidence: 0.6,
		},
		Relations: []detect.RelationClaim{
			{Type: airom.RelEmbedsWith, Target: detect.TargetHint{Kind: airom.KindEmbeddingModel, Name: emb.Claim.Name}},
			{Type: airom.RelContains, Target: detect.TargetHint{Kind: airom.KindVectorDB, Name: vdb.Claim.Name}},
		},
	}
	return []detect.Finding{f}, nil
}
