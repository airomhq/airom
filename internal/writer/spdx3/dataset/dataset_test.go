package dataset

import (
	"testing"
	"time"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

func TestDatasetProfile_Translation(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	creationInfo := &spdx3.CreationInfo{
		SpecVersion: spdx3.SpecVersion,
		Created:     time.Now().UTC(),
		CreatedBy:   []string{"https://spdx.org/spdxdocs/test/agent/airom"},
	}

	comp := &airom.Component{
		ID:       "airom:squad_v2",
		Kind:     airom.KindDataset,
		Name:     "squad_v2",
		Provider: airom.KnownString("rajpurkar"),
		Version:  airom.KnownString("2.0"),
		PURL:     "pkg:generic/squad_v2@2.0",
		Licenses: []airom.License{{SPDXID: "CC-BY-SA-4.0"}},
		Hashes: []airom.Hash{
			{Alg: "SHA-256", Hex: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
		},
		Data: &airom.DataFacet{
			Format:    airom.KnownString("json"),
			SizeBytes: airom.KnownInt64(45000000),
			URL:       airom.KnownString("https://rajpurkar.github.io/SQuAD-explorer/dataset/train-v2.0.json"),
		},
	}

	ds, _ := translator.TranslateDataset(comp, creationInfo)
	if ds == nil {
		t.Fatalf("expected non-nil Dataset")
	}

	if ds.DataFormat != "json" {
		t.Errorf("expected format json, got %s", ds.DataFormat)
	}
	if ds.SizeBytes != 45000000 {
		t.Errorf("expected size 45000000, got %d", ds.SizeBytes)
	}
	if ds.DatasetURL != "https://rajpurkar.github.io/SQuAD-explorer/dataset/train-v2.0.json" {
		t.Errorf("expected dataset URL, got %s", ds.DatasetURL)
	}
	if ds.DeclaredLicense != "CC-BY-SA-4.0" {
		t.Errorf("expected CC-BY-SA-4.0 license, got %s", ds.DeclaredLicense)
	}
}

func TestDatasetProfile_SparseDataset(t *testing.T) {
	serializer := spdx3.NewSerializer("https://spdx.org/spdxdocs/test")
	translator := NewTranslator(serializer)

	comp := &airom.Component{
		ID:   "airom:sparse_ds",
		Kind: airom.KindDataset,
		Name: "bare-dataset",
	}

	ds, _ := translator.TranslateDataset(comp, &spdx3.CreationInfo{})
	if ds == nil {
		t.Fatalf("expected non-nil dataset")
	}
	if ds.PackageVersion != spdx3.NoAssertion {
		t.Errorf("expected NOASSERTION packageVersion, got %s", ds.PackageVersion)
	}
}
