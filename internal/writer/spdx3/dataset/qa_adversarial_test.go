package dataset

import (
	"math"
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

func TestQA_AdversarialExtremeDatasetSizes(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	comp := &airom.Component{
		ID:   "airom:extreme_ds",
		Kind: airom.KindDataset,
		Name: "petabyte-dataset",
		Data: &airom.DataFacet{
			SizeBytes: airom.KnownInt64(math.MaxInt64),
		},
	}

	ds, _ := translator.TranslateDataset(comp, &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()})
	if ds == nil {
		t.Fatalf("expected non-nil Dataset")
	}

	if ds.SizeBytes != math.MaxInt64 {
		t.Errorf("expected max int64 size, got %d", ds.SizeBytes)
	}
}

func TestQA_AdversarialMaliciousURLsAndLicenses(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	maliciousURLs := []string{
		"javascript:alert(1)",
		"file:///etc/shadow",
		"https://evil.com/dataset?payload=<script>steal()</script>",
	}

	for _, malURL := range maliciousURLs {
		comp := &airom.Component{
			ID:   "airom:mal_ds",
			Kind: airom.KindDataset,
			Name: "mal-dataset",
			Data: &airom.DataFacet{
				URL: airom.KnownString(malURL),
			},
			Licenses: []airom.License{{Name: malURL}},
		}

		ds, _ := translator.TranslateDataset(comp, &spdx3.CreationInfo{SpecVersion: spdx3.SpecVersion, Created: time.Now().UTC()})
		if ds == nil {
			t.Fatalf("failed on malicious URL %q", malURL)
		}
		if ds.DatasetURL != malURL {
			t.Errorf("URL mismatch: got %s, want %s", ds.DatasetURL, malURL)
		}
	}
}

func TestQA_AdversarialNilPointers(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	// Nil component
	ds, elems := translator.TranslateDataset(nil, nil)
	if ds != nil || elems != nil {
		t.Fatalf("expected nil for nil component")
	}

	// Bare component with nil DataFacet
	comp := &airom.Component{
		ID:   "airom:bare_ds",
		Kind: airom.KindDataset,
		Name: "bare",
	}
	ds, _ = translator.TranslateDataset(comp, &spdx3.CreationInfo{})
	if ds == nil {
		t.Fatalf("expected non-nil dataset for bare component")
	}
}
