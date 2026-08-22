package report

import (
	"fmt"
	"os"
	"strings"
)

// LLMProvider represents the supported LLM backends for ReportEngine.
type LLMProvider string

const (
	ProviderAnthropic LLMProvider = "anthropic"
	ProviderOpenAI    LLMProvider = "openai"
	ProviderAzure     LLMProvider = "azure"
	ProviderOllama    LLMProvider = "ollama" // Local air-gapped execution
)

// LLMBackendConfig holds settings for BYOK (Bring-Your-Own-Key) LLM integration.
type LLMBackendConfig struct {
	Provider    LLMProvider `json:"provider" yaml:"provider"`
	APIKeyEnv   string      `json:"api_key_env" yaml:"api_key_env"`
	Model       string      `json:"model" yaml:"model"`
	BaseURL     string      `json:"base_url,omitempty" yaml:"base_url,omitempty"`
	AirGapped   bool        `json:"air_gapped" yaml:"air_gapped"`
	MaxTokens   int         `json:"max_tokens" yaml:"max_tokens"`
	Temperature float64     `json:"temperature" yaml:"temperature"`
}

// EngineConfig holds configuration for the ReportEngine service and on-prem container.
type EngineConfig struct {
	Endpoint     string           `json:"endpoint" yaml:"endpoint"`
	LLMBackend   LLMBackendConfig `json:"llm_backend" yaml:"llm_backend"`
	DefaultOrg   string           `json:"default_org,omitempty" yaml:"default_org,omitempty"`
	OutputFormat string           `json:"output_format,omitempty" yaml:"output_format,omitempty"` // markdown, html, json, all
}

// DefaultEngineConfig returns standard secure defaults.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		Endpoint: "http://localhost:8080/v1",
		LLMBackend: LLMBackendConfig{
			Provider:    ProviderOllama,
			APIKeyEnv:   "",
			Model:       "llama3:8b",
			AirGapped:   true,
			MaxTokens:   4096,
			Temperature: 0.1,
		},
		OutputFormat: "all",
	}
}

// Validate checks configuration integrity.
func (c *EngineConfig) Validate() error {
	p := strings.ToLower(string(c.LLMBackend.Provider))
	switch LLMProvider(p) {
	case ProviderAnthropic, ProviderOpenAI, ProviderAzure, ProviderOllama:
		// valid
	default:
		return fmt.Errorf("unsupported llm provider: %q (must be anthropic, openai, azure, or ollama)", c.LLMBackend.Provider)
	}

	if !c.LLMBackend.AirGapped && c.LLMBackend.Provider != ProviderOllama && c.LLMBackend.APIKeyEnv != "" {
		if os.Getenv(c.LLMBackend.APIKeyEnv) == "" {
			return fmt.Errorf("required API key environment variable %q is not set", c.LLMBackend.APIKeyEnv)
		}
	}

	return nil
}
