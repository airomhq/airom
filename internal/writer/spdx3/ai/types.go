// Package ai implements the formal SPDX 3.0.1 AI Profile (ARCHITECTURE.md §11, docs/mapping.md).
package ai

import (
	"github.com/airomhq/airom/internal/writer/spdx3"
)

const (
	// TypeAIModel is the canonical SPDX 3.0.1 AI Profile element type for AI Models.
	TypeAIModel = "AIModel"
	// TypeAIPackage is the canonical element type for packages carrying AI assets.
	TypeAIPackage = "AIPackage"
	// TypeHyperparameter is the canonical element type for model hyperparameters.
	TypeHyperparameter = "Hyperparameter"
	// TypeEnergyConsumption is the element type for energy accounting.
	TypeEnergyConsumption = "EnergyConsumption"
	// TypeSafetyLimits records boundary conditions and guardrails.
	TypeSafetyLimits = "SafetyLimits"
)

// Hyperparameter represents a model training or generation configuration parameter.
type Hyperparameter struct {
	spdx3.BaseElement
	ParameterKey   string `json:"parameterKey"`
	ParameterValue string `json:"parameterValue"`
	ContextLine    int    `json:"contextLine,omitempty"`
	SourceFile     string `json:"sourceFile,omitempty"`
}

// EnergyConsumption records environmental metrics pursuant to statutory disclosures.
type EnergyConsumption struct {
	spdx3.BaseElement
	Activity string  `json:"activity"` // training | fine-tuning | inference
	KWh      float64 `json:"kWh"`
}

// SafetyLimits defines operational guardrails, technical limitations, and user constraints.
type SafetyLimits struct {
	spdx3.BaseElement
	Users                []string `json:"users,omitempty"`
	UseCases             []string `json:"useCases,omitempty"`
	TechnicalLimitations []string `json:"technicalLimitations,omitempty"`
}

// AIModel represents an artificial intelligence model in the SPDX 3.0.1 graph.
type AIModel struct {
	spdx3.Package
	ModelType          string              `json:"modelType,omitempty"` // foundation | fine-tune | adapter | embedding
	ModelArchitecture  string              `json:"modelArchitecture,omitempty"`
	ParameterCount     int64               `json:"parameterCount,omitempty"`
	Quantization       string              `json:"quantization,omitempty"`
	ContextWindow      int64               `json:"contextWindow,omitempty"`
	TaskCategory       string              `json:"taskCategory,omitempty"`
	BaseModelRef       string              `json:"baseModelRef,omitempty"`
	Hyperparameters    []Hyperparameter    `json:"hyperparameters,omitempty"`
	EnergyMetrics      []EnergyConsumption `json:"energyMetrics,omitempty"`
	SafetyLimits       *SafetyLimits       `json:"safetyLimits,omitempty"`
	StandardCompliance []string            `json:"standardCompliance,omitempty"` // Colorado AI Act, EU AI Act, ISO 42001
}
