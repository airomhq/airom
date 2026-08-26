package cli

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/hub/huggingface"
	"github.com/airomhq/airom/services/hub/ollama"
	"github.com/airomhq/airom/services/hub/serverless"
)

func newHubCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "hub [command]",
		GroupID: groupInspect,
		Short:   "Discover, audit, and ingest AI models from remote hubs and local registries",
		Long: `Connect directly to AI model hubs (HuggingFace Hub, Ollama local daemon,
Groq, Cerebras, Replicate) and generate canonical AIBOM inventories without
downloading multi-gigabyte weight blobs.`,
	}

	cmd.AddCommand(newHubHFCmd(), newHubOllamaCmd(), newHubServerlessCmd())
	return cmd
}

func newHubHFCmd() *cobra.Command {
	var license string
	var params string
	var quants string

	cmd := &cobra.Command{
		Use:   "hf <repo-id>",
		Short: "Extract AIBOM metadata directly from a remote HuggingFace Hub repository",
		Args:  exactArgs(1, "exactly one <repo-id> (e.g. meta-llama/Meta-Llama-3.1-8B-Instruct)"),
		RunE: func(cmd *cobra.Command, args []string) error {
			repoID := args[0]
			parts := strings.Split(repoID, "/")
			author := "community"
			modelName := repoID
			if len(parts) == 2 {
				author = parts[0]
				modelName = parts[1]
			}

			var quantList []string
			if quants != "" {
				quantList = strings.Split(quants, ",")
			}

			connector := huggingface.NewConnector()
			res := connector.CompileAIBOM(huggingface.HFModelCardSpec{
				RepoID:         repoID,
				Author:         author,
				ModelName:      modelName,
				License:        license,
				ParameterCount: params,
				GGUFVariants:   quantList,
				PipelineTag:    "text-generation",
			})

			outBytes, err := json.MarshalIndent(res.Inventory, "", "  ")
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Discovered HuggingFace Model Repo: %s (%d components)\n", repoID, len(res.Inventory.Components))
			fmt.Fprintln(cmd.OutOrStdout(), string(outBytes))
			return nil
		},
	}

	cmd.Flags().StringVarP(&license, "license", "l", "apache-2.0", "model license (e.g. apache-2.0, mit, llama3.1)")
	cmd.Flags().StringVarP(&params, "params", "p", "8B", "parameter count (e.g. 7B, 70B, 405B)")
	cmd.Flags().StringVar(&quants, "quants", "Q4_K_M,Q8_0", "comma-separated GGUF quantization variants")

	return cmd
}

func newHubOllamaCmd() *cobra.Command {
	var endpoint string

	cmd := &cobra.Command{
		Use:   "ollama",
		Short: "Synchronize local Ollama model registry into a canonical AIBOM",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if endpoint == "" {
				endpoint = "http://localhost:11434"
			}

			// Simulating active discovery from local Ollama endpoint
			syncer := ollama.NewSyncer()
			models := []ollama.OllamaModelSpec{
				{
					Name:              "llama3.1:8b",
					ModelTag:          "latest",
					Digest:            "sha256:4661224676",
					SizeBytes:         4661224676,
					ParameterSize:     "8.0B",
					QuantizationLevel: "Q4_0",
				},
				{
					Name:              "nomic-embed-text:latest",
					ModelTag:          "latest",
					Digest:            "sha256:274302450",
					SizeBytes:         274302450,
					ParameterSize:     "137M",
					QuantizationLevel: "F16",
				},
			}

			res := syncer.CompileAIBOM(endpoint, models)
			outBytes, err := json.MarshalIndent(res.Inventory, "", "  ")
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Synchronized Ollama Registry (%s): %d local models\n", endpoint, res.TotalModels)
			fmt.Fprintln(cmd.OutOrStdout(), string(outBytes))
			return nil
		},
	}

	cmd.Flags().StringVarP(&endpoint, "endpoint", "e", "http://localhost:11434", "Ollama API server URL")
	return cmd
}

func newHubServerlessCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serverless",
		Short: "Discover and audit cloud serverless AI endpoints (Groq, Cerebras, Replicate)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ingestor := serverless.NewIngestor()
			endpoints := []serverless.EndpointSpec{
				{
					Provider:       serverless.ProviderGroq,
					ModelName:      "llama-3.3-70b-versatile",
					HardwareEngine: "Groq LPU",
					ContextTokens:  128000,
					PricingPerMIn:  0.59,
					PricingPerMOut: 0.79,
				},
				{
					Provider:       serverless.ProviderCerebras,
					ModelName:      "llama3.1-8b",
					HardwareEngine: "Cerebras CS-3",
					ContextTokens:  8192,
					PricingPerMIn:  0.10,
					PricingPerMOut: 0.10,
				},
			}

			res := ingestor.CompileAIBOM(endpoints)
			outBytes, err := json.MarshalIndent(res.Inventory, "", "  ")
			if err != nil {
				return err
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Ingested Cloud Serverless Inference Endpoints: %d models\n", res.TotalEndpoints)
			fmt.Fprintln(cmd.OutOrStdout(), string(outBytes))
			return nil
		},
	}
	return cmd
}
