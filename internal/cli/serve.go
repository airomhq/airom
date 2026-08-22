package cli

import (
	"fmt"
	"log/slog"

	"github.com/spf13/cobra"

	"github.com/airomhq/airom/services/server"
)

func newServeCmd() *cobra.Command {
	var (
		host             string
		port             int
		jwtSecret        string
		auditSigningKey  string
		stripeSecret     string
		humanTokenSecret string
	)

	cmd := &cobra.Command{
		Use:     "serve",
		GroupID: groupDev,
		Short:   "Start the AIROM Enterprise Governance & Compliance API Gateway",
		Long: `Start the unified AIROM Enterprise Server Gateway daemon, exposing REST APIs for
Enterprise SSO/RBAC, ComplianceDB Ledger, Anomaly Engine, ReportEngine, Document Review Gateway,
SOC 2 Audit & SIEM Streaming, and Stripe Commercial Billing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg := server.DefaultConfig()
			if host != "" {
				cfg.Host = host
			}
			if port > 0 {
				cfg.Port = port
			}
			if jwtSecret != "" {
				cfg.JWTSecret = jwtSecret
			}
			if auditSigningKey != "" {
				cfg.AuditSigningKey = auditSigningKey
			}
			if stripeSecret != "" {
				cfg.StripeSecret = stripeSecret
			}
			if humanTokenSecret != "" {
				cfg.HumanTokenSecret = humanTokenSecret
			}

			slog.Info("Initializing AIROM Enterprise Server", "host", cfg.Host, "port", cfg.Port)
			srv := server.NewEnterpriseServer(cfg)
			fmt.Fprintf(cmd.OutOrStdout(), "AIROM Enterprise Gateway listening on http://%s:%d\n", cfg.Host, cfg.Port)
			return srv.RunWithGracefulShutdown()
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&host, "host", "H", "0.0.0.0", "Bind host address")
	flags.IntVarP(&port, "port", "p", 8080, "Bind HTTP port")
	flags.StringVar(&jwtSecret, "jwt-secret", "", "Enterprise JWT signing secret (or AIROM_JWT_SECRET env)")
	flags.StringVar(&auditSigningKey, "audit-signing-key", "", "SOC 2 Audit HMAC signing key")
	flags.StringVar(&stripeSecret, "stripe-secret", "", "Stripe webhook signing secret")
	flags.StringVar(&humanTokenSecret, "human-token-secret", "", "Human Review Gateway HMAC secret")

	return cmd
}
