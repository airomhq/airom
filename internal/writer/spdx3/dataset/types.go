// Package dataset implements the formal SPDX 3.0.1 Dataset Profile (ARCHITECTURE.md §11).
package dataset

import (
	"github.com/airomhq/airom/internal/writer/spdx3"
)

const (
	// TypeDataset is the canonical SPDX 3.0.1 element type for datasets.
	TypeDataset = "Dataset"
	// TypeDataCollection is the element type for collection provenance.
	TypeDataCollection = "DataCollection"
)

// DataSplit records the partition ratios across training, validation, and testing.
type DataSplit struct {
	TrainPercent      float64 `json:"trainPercent,omitempty"`
	ValidationPercent float64 `json:"validationPercent,omitempty"`
	TestPercent       float64 `json:"testPercent,omitempty"`
}

// SensitiveDataProfile tracks PII, biometrics, and anonymization status.
type SensitiveDataProfile struct {
	ContainsPII         bool   `json:"containsPii"`
	ContainsBiometrics  bool   `json:"containsBiometrics"`
	AnonymizationMethod string `json:"anonymizationMethod,omitempty"`
}

// Dataset represents a dataset element in the SPDX 3.0.1 graph.
type Dataset struct {
	spdx3.Package
	DatasetType           string                `json:"datasetType,omitempty"` // synthetic | scraped | curated | annotated | noAssertion
	DataCollectionProcess string                `json:"dataCollectionProcess,omitempty"`
	DataPreprocessing     string                `json:"dataPreprocessing,omitempty"`
	DataFormat            string                `json:"dataFormat,omitempty"` // csv | jsonl | parquet | arrow | hf-dataset
	SizeBytes             int64                 `json:"sizeBytes,omitempty"`
	DatasetURL            string                `json:"datasetUrl,omitempty"`
	DataSplit             *DataSplit            `json:"dataSplit,omitempty"`
	SensitiveData         *SensitiveDataProfile `json:"sensitiveData,omitempty"`
	KnownBiases           []string              `json:"knownBiases,omitempty"`
	IntendedUse           string                `json:"intendedUse,omitempty"`
}
