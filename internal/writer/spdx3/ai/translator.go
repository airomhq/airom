package ai

import (
	"fmt"
	"strings"

	"github.com/airomhq/airom/internal/writer/spdx3"
	"github.com/airomhq/airom/pkg/airom"
)

// Translator projects AIROM model components into SPDX 3.0.1 AI Profile elements.
type Translator struct {
	serializer *spdx3.Serializer
}

// NewTranslator constructs an AI Profile translator.
func NewTranslator(serializer *spdx3.Serializer) *Translator {
	return &Translator{serializer: serializer}
}

// TranslateModel projects an airom.Component into an SPDX 3.0.1 AIModel element.
func (t *Translator) TranslateModel(c *airom.Component, creationInfo *spdx3.CreationInfo) (*AIModel, []spdx3.Element) {
	if c == nil {
		return nil, nil
	}

	spdxID := t.serializer.CanonicalID(string(c.Kind), string(c.ID))

	providerStr := spdx3.NoAssertion
	if v, ok := c.Provider.Value(); ok && v != "" {
		providerStr = v
	}

	verStr := spdx3.NoAssertion
	if v, ok := c.Version.Value(); ok && v != "" {
		verStr = v
	}

	aiModel := &AIModel{
		Package: spdx3.Package{
			BaseElement: spdx3.BaseElement{
				Type:         TypeAIModel,
				SpdxID:       spdxID,
				CreationInfo: creationInfo,
				Name:         c.Name,
				Summary:      fmt.Sprintf("%s (%s model by %s)", c.Name, c.Kind, providerStr),
			},
			PackageVersion:   verStr,
			DownloadLocation: spdx3.NoAssertion,
			PrimaryPurpose:   "machineLearningModel",
			SuppliedBy:       providerStr,
		},
		ModelType: string(c.Kind),
	}

	if c.PURL != "" {
		aiModel.ExternalIdentifier = append(aiModel.ExternalIdentifier, spdx3.ExternalIdentifier{
			Type:                   "ExternalIdentifier",
			ExternalIdentifierType: "purl",
			Identifier:             c.PURL,
		})
	}

	for _, h := range c.Hashes {
		aiModel.VerifiedUsing = append(aiModel.VerifiedUsing, spdx3.IntegrityMethod{
			Type:      "Hash",
			Algorithm: strings.ToLower(h.Alg),
			HashValue: h.Hex,
		})
	}

	var childElements []spdx3.Element

	if c.Model != nil {
		if arch, ok := c.Model.Architecture.Value(); ok {
			aiModel.ModelArchitecture = arch
		}
		if params, ok := c.Model.ParamCount.Value(); ok {
			aiModel.ParameterCount = params
		}
		if quant, ok := c.Model.Quantization.Value(); ok {
			aiModel.Quantization = quant
		}
		if ctxLen, ok := c.Model.ContextLength.Value(); ok {
			aiModel.ContextWindow = ctxLen
		}
		if task, ok := c.Model.Task.Value(); ok {
			aiModel.TaskCategory = task
		}
		if base, ok := c.Model.BaseModel.Value(); ok {
			aiModel.BaseModelRef = t.serializer.CanonicalID("base-model", base)
		}

		// Map generation hyperparameters
		for i, param := range c.Model.GenerationParams {
			hpID := t.serializer.CanonicalID("hyperparameter", fmt.Sprintf("%s-param-%d-%s", c.ID, i, param.Name))
			hp := Hyperparameter{
				BaseElement: spdx3.BaseElement{
					Type:         TypeHyperparameter,
					SpdxID:       hpID,
					CreationInfo: creationInfo,
					Name:         param.Name,
				},
				ParameterKey:   param.Name,
				ParameterValue: param.Value,
			}
			if param.Occurrence != nil {
				hp.ContextLine = param.Occurrence.Location.Line
				hp.SourceFile = param.Occurrence.Location.Path
			}
			aiModel.Hyperparameters = append(aiModel.Hyperparameters, hp)
		}

		// Map ModelCard considerations and energy metrics
		if c.Model.Card != nil {
			if c.Model.Card.Considerations != nil {
				limitsID := t.serializer.CanonicalID("safety-limits", fmt.Sprintf("%s-limits", c.ID))
				aiModel.SafetyLimits = &SafetyLimits{
					BaseElement: spdx3.BaseElement{
						Type:         TypeSafetyLimits,
						SpdxID:       limitsID,
						CreationInfo: creationInfo,
					},
					Users:                c.Model.Card.Considerations.Users,
					UseCases:             c.Model.Card.Considerations.UseCases,
					TechnicalLimitations: c.Model.Card.Considerations.TechnicalLimitations,
				}
			}

			for i, energy := range c.Model.Card.Energy {
				energyID := t.serializer.CanonicalID("energy", fmt.Sprintf("%s-energy-%d", c.ID, i))
				aiModel.EnergyMetrics = append(aiModel.EnergyMetrics, EnergyConsumption{
					BaseElement: spdx3.BaseElement{
						Type:         TypeEnergyConsumption,
						SpdxID:       energyID,
						CreationInfo: creationInfo,
					},
					Activity: energy.Activity,
					KWh:      energy.KWh,
				})
			}
		}
	}

	return aiModel, childElements
}
