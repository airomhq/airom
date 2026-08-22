package app

import (
	"context"
	"testing"

	"github.com/airomhq/airom/pkg/airom"
)

// TestAssuranceSurvivesStatsReset pins the emit() reset: without --stats the
// volatile counters are dropped, but the assurance fields say what the scan
// did NOT see, and dropping them would make a partial scan byte-identical to
// a complete one — the same argument that keeps Warnings alive.
func TestAssuranceSurvivesStatsReset(t *testing.T) {
	inv := &airom.Inventory{
		Stats: airom.ScanStats{
			FilesWalked:     10,
			FilesIgnored:    3,
			DirsPruned:      2,
			FilesTruncated:  1,
			HeaderBytes:     999, // volatile: must be dropped
			ConfidenceModel: airom.ConfidenceModelV1,
			Enrichment: &airom.EnrichmentStats{
				CVE: airom.CVEEnrichment{Enabled: true, Unchecked: 4},
				EOL: airom.EOLEnrichment{Enabled: true, CatalogLoaded: true},
			},
		},
	}
	cfg := &Config{Stats: false, Outputs: nil}
	if err := emit(context.Background(), inv, cfg); err != nil {
		t.Fatal(err)
	}
	st := inv.Stats
	if st.HeaderBytes != 0 {
		t.Error("volatile HeaderBytes survived the reset")
	}
	if st.FilesIgnored != 3 || st.DirsPruned != 2 || st.FilesTruncated != 1 {
		t.Errorf("assurance counters dropped: ignored=%d pruned=%d truncated=%d",
			st.FilesIgnored, st.DirsPruned, st.FilesTruncated)
	}
	if st.ConfidenceModel != airom.ConfidenceModelV1 {
		t.Error("ConfidenceModel dropped by the reset")
	}
	if st.Enrichment == nil || st.Enrichment.CVE.Unchecked != 4 {
		t.Error("Enrichment dropped by the reset: 'no CVE check' now looks like 'no CVEs'")
	}
}
