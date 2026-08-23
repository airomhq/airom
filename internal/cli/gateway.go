package cli

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/gateway"
)

func newGatewayCmd() *cobra.Command {
	var (
		port                int
		approvedModels      string
		maxTemp             float64
		maxTokens           int
		enableRedaction     bool
		circuitBreakerLimit int
		upstreamURL         string
	)

	cmd := &cobra.Command{
		Use:     "gateway",
		GroupID: groupDev,
		Short:   "Start the AIROM Runtime AI Security Gateway & Governance Proxy",
		Long: `Start the runtime AI security proxy enforcing model whitelisting (.airomapproved),
real-time PII & secret redaction, parameter clamping ceilings, and agentic runaway loop circuit breaker.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var models []string
			if approvedModels != "" {
				for _, m := range strings.Split(approvedModels, ",") {
					if trimmed := strings.TrimSpace(m); trimmed != "" {
						models = append(models, trimmed)
					}
				}
			}

			cfg := gateway.GatewayConfig{
				ApprovedModels:                  models,
				MaxTemperature:                  maxTemp,
				MaxTokens:                       maxTokens,
				EnableRedaction:                 enableRedaction,
				CircuitBreakerMaxCallsPerMinute: circuitBreakerLimit,
				UpstreamURL:                     upstreamURL,
			}

			srv := gateway.NewServer(cfg)
			addr := fmt.Sprintf("0.0.0.0:%d", port)
			slog.Info("Starting AIROM Runtime AI Security Gateway Proxy", "addr", addr)
			fmt.Fprintf(cmd.OutOrStdout(), "AIROM Security Gateway listening on http://%s\n", addr)
			return http.ListenAndServe(addr, srv.Routes())
		},
	}

	flags := cmd.Flags()
	flags.IntVarP(&port, "port", "p", 8081, "Bind port for security gateway")
	flags.StringVar(&approvedModels, "approved-models", "", "Comma-separated list of approved model IDs")
	flags.Float64Var(&maxTemp, "max-temp", 0.7, "Maximum allowed generation temperature ceiling")
	flags.IntVar(&maxTokens, "max-tokens", 4096, "Maximum allowed generation tokens ceiling")
	flags.BoolVar(&enableRedaction, "redact", true, "Enable real-time PII & secret stream redaction")
	flags.IntVar(&circuitBreakerLimit, "circuit-breaker", 30, "Maximum agentic tool calls allowed per minute before tripping")
	flags.StringVar(&upstreamURL, "upstream", "", "Upstream LLM / MCP endpoint URL to proxy to")

	return cmd
}
