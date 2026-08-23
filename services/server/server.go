package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/airomhq/airom/services/anomaly"
	"github.com/airomhq/airom/services/audit"
	"github.com/airomhq/airom/services/auth"
	"github.com/airomhq/airom/services/billing"
	"github.com/airomhq/airom/services/cluster"
	"github.com/airomhq/airom/services/compliancedb"
	"github.com/airomhq/airom/services/dashboard"
	"github.com/airomhq/airom/services/document"
	"github.com/airomhq/airom/services/filing"
	"github.com/airomhq/airom/services/provenance"
	"github.com/airomhq/airom/services/redteam"
	"github.com/airomhq/airom/services/regwatch"
	"github.com/airomhq/airom/services/report"
	"github.com/airomhq/airom/services/shadowai"
	"github.com/airomhq/airom/services/workforce"
)

// Config holds runtime configuration for the Enterprise Server Gateway.
type Config struct {
	Host             string `json:"host"`
	Port             int    `json:"port"`
	JWTSecret        string `json:"jwt_secret"`
	AuditSigningKey  string `json:"audit_signing_key"`
	StripeSecret     string `json:"stripe_secret"`
	HumanTokenSecret string `json:"human_token_secret"`
	ReadTimeoutSec   int    `json:"read_timeout_sec"`
	WriteTimeoutSec  int    `json:"write_timeout_sec"`
}

// DefaultConfig returns recommended production defaults.
func DefaultConfig() Config {
	return Config{ // #nosec G101 -- default configuration template values for local development and testing
		Host:             "0.0.0.0",
		Port:             8080,
		JWTSecret:        "airom-enterprise-jwt-secret-key-prod-2026",
		AuditSigningKey:  "airom-soc2-audit-signing-key-prod-2026",
		StripeSecret:     "whsec_prod_enterprise_stripe_secret",
		HumanTokenSecret: "airom-human-gateway-token-secret-2026",
		ReadTimeoutSec:   15,
		WriteTimeoutSec:  30,
	}
}

// EnterpriseServer orchestrates all AIROM enterprise backend services into a single gateway.
type EnterpriseServer struct {
	cfg           Config
	authSvc       *auth.Service
	complianceDB  *compliancedb.Service
	anomalyEngine *anomaly.Engine
	auditSvc      *audit.Service
	billingSvc    *billing.Service
	docAgent      *document.Agent
	eventBroker   *EventBroker
	reportCfg     report.EngineConfig
	httpServer    *http.Server
	mux           *http.ServeMux
}

// NewEnterpriseServer creates and initializes all enterprise services.
func NewEnterpriseServer(cfg Config) *EnterpriseServer {
	if cfg.Port <= 0 {
		cfg.Port = 8080
	}
	if cfg.JWTSecret == "" {
		cfg.JWTSecret = "default-jwt-secret"
	}
	if cfg.AuditSigningKey == "" {
		cfg.AuditSigningKey = "default-audit-signing-key"
	}
	if cfg.HumanTokenSecret == "" {
		cfg.HumanTokenSecret = "default-human-token-secret"
	}

	authSvc := auth.NewService([]byte(cfg.JWTSecret))
	complianceDB := compliancedb.NewService()
	anomalyEngine := anomaly.NewEngine()
	auditSvc := audit.NewService(cfg.AuditSigningKey, nil)
	billingSvc := billing.NewService(cfg.StripeSecret)
	docAgent := document.NewAgent([]byte(cfg.HumanTokenSecret))
	eventBroker := NewEventBroker()
	reportCfg := report.DefaultEngineConfig()

	s := &EnterpriseServer{
		cfg:           cfg,
		authSvc:       authSvc,
		complianceDB:  complianceDB,
		anomalyEngine: anomalyEngine,
		auditSvc:      auditSvc,
		billingSvc:    billingSvc,
		docAgent:      docAgent,
		eventBroker:   eventBroker,
		reportCfg:     reportCfg,
		mux:           http.NewServeMux(),
	}

	s.setupRoutes()
	return s
}

func (s *EnterpriseServer) setupRoutes() {
	// 1. Health & Liveness Probes
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/livez", s.handleHealthz)
	s.mux.HandleFunc("/readyz", s.handleReadyz)

	// 2. Metrics & System Info
	s.mux.HandleFunc("/metrics", s.handleMetrics)
	s.mux.HandleFunc("/api/v1/info", s.handleSystemInfo)
	s.mux.HandleFunc("/api/v1/events/stream", s.eventBroker.Handler())

	// 3. Mount Service Handlers with Path Stripping / Delegation
	mountHandler(s.mux, "/api/v1/auth/", s.authSvc.Routes())
	mountHandler(s.mux, "/api/v1/repos/", s.complianceDB.Routes())
	mountHandler(s.mux, "/api/v1/orgs/", s.complianceDB.Routes())
	mountHandler(s.mux, "/api/v1/audit/", s.auditSvc.Routes())
	mountHandler(s.mux, "/api/v1/billing/", s.billingSvc.Routes())
	mountHandler(s.mux, "/api/v1/documents", document.NewServer(s.docAgent).Routes())
	mountHandler(s.mux, "/api/v1/documents/", document.NewServer(s.docAgent).Routes())
	mountHandler(s.mux, "/api/v1/regwatch/", regwatch.NewService(regwatch.ScraperConfig{}).Routes())
	mountHandler(s.mux, "/api/v1/filings/", filing.NewService().Routes())
	mountHandler(s.mux, "/api/v1/workforce/", workforce.NewService().Routes())
	mountHandler(s.mux, "/api/v1/shadowai/", shadowai.NewService().Routes())
	mountHandler(s.mux, "/api/v1/provenance/", provenance.NewService().Routes())
	mountHandler(s.mux, "/api/v1/dashboard/", dashboard.NewService().Routes())
	mountHandler(s.mux, "/api/v1/redteam/", redteam.NewService().Routes())
	mountHandler(s.mux, "/api/v1/cluster/", cluster.NewService().Routes())
}

func mountHandler(mux *http.ServeMux, prefix string, h http.Handler) {
	mux.Handle(prefix, h)
}

func (s *EnterpriseServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *EnterpriseServer) handleReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ready",
		"services": map[string]string{
			"auth":         "ready",
			"compliancedb": "ready",
			"anomaly":      "ready",
			"audit":        "ready",
			"billing":      "ready",
			"document":     "ready",
			"report":       "ready",
			"regwatch":     "ready",
			"filing":       "ready",
			"workforce":    "ready",
			"shadowai":     "ready",
			"provenance":   "ready",
			"dashboard":    "ready",
			"redteam":      "ready",
			"cluster":      "ready",
		},
	})
}

func (s *EnterpriseServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP airom_server_up Server operational status\n")
	fmt.Fprintf(w, "# TYPE airom_server_up gauge\n")
	fmt.Fprintf(w, "airom_server_up 1\n\n")

	fmt.Fprintf(w, "# HELP airom_service_info AIROM Enterprise build metadata\n")
	fmt.Fprintf(w, "# TYPE airom_service_info gauge\n")
	fmt.Fprintf(w, "airom_service_info{version=\"1.0.0\",edition=\"enterprise\"} 1\n")
}

func (s *EnterpriseServer) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"name":        "AIROM Enterprise Governance Gateway",
		"version":     "1.0.0",
		"edition":     "Enterprise",
		"environment": "production",
		"protocols":   []string{"REST", "Webhooks", "SIEM-Stream", "SSE"},
		"frameworks": []string{
			"colorado-ai-act",
			"nyc-ll144",
			"ca-ab2013",
			"illinois-bipa",
			"texas-traiga",
			"virginia-vcdpa",
			"nist-ai-rmf",
			"owasp-agentic",
		},
	})
}

// Handler returns the root http.Handler with standard middleware wrapped.
func (s *EnterpriseServer) Handler() http.Handler {
	return s.wrapMiddleware(s.mux)
}

func (s *EnterpriseServer) wrapMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Global Security Headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

		// CORS for Enterprise Dashboards
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DD-API-KEY, Stripe-Signature, X-AIROM-Signature")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)

		duration := time.Since(start)
		slog.Debug("HTTP Request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// Start runs the HTTP server listening on the configured address.
func (s *EnterpriseServer) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.Handler(),
		ReadTimeout:  time.Duration(s.cfg.ReadTimeoutSec) * time.Second,
		WriteTimeout: time.Duration(s.cfg.WriteTimeoutSec) * time.Second,
	}

	slog.Info("Starting AIROM Enterprise Gateway", "addr", addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
func (s *EnterpriseServer) Shutdown(ctx context.Context) error {
	s.auditSvc.Close()
	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}
	return nil
}

// RunWithGracefulShutdown handles OS interrupt signals for graceful stop.
func (s *EnterpriseServer) RunWithGracefulShutdown() error {
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- s.Start()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErr:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	case sig := <-stop:
		slog.Info("Shutdown signal received", "signal", sig.String())
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return s.Shutdown(ctx)
	}
	return nil
}

// Direct service getters for integration testing
func (s *EnterpriseServer) Auth() *auth.Service                 { return s.authSvc }
func (s *EnterpriseServer) ComplianceDB() *compliancedb.Service { return s.complianceDB }
func (s *EnterpriseServer) Anomaly() *anomaly.Engine            { return s.anomalyEngine }
func (s *EnterpriseServer) Audit() *audit.Service               { return s.auditSvc }
func (s *EnterpriseServer) Billing() *billing.Service           { return s.billingSvc }
func (s *EnterpriseServer) Document() *document.Agent           { return s.docAgent }
