package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// GatewayConfig defines the policy and routing rules for the AI runtime security proxy.
type GatewayConfig struct {
	ApprovedModels                  []string `json:"approved_models"`
	MaxTemperature                  float64  `json:"max_temperature"`
	MaxTokens                       int      `json:"max_tokens"`
	EnableRedaction                 bool     `json:"enable_redaction"`
	CircuitBreakerMaxCallsPerMinute int      `json:"circuit_breaker_max_calls_per_minute"`
	UpstreamURL                     string   `json:"upstream_url"`
}

// Server is the HTTP gateway proxy enforcing model whitelisting, parameter clamping, redaction, and runaway loop protection.
type Server struct {
	mu             sync.RWMutex
	config         GatewayConfig
	approvedMap    map[string]bool
	redactor       *Redactor
	circuitBreaker *CircuitBreaker
	client         *http.Client
	mux            *http.ServeMux
}

// NewServer constructs and initializes the gateway proxy with active governance policies.
func NewServer(cfg GatewayConfig) *Server {
	if cfg.MaxTemperature <= 0 {
		cfg.MaxTemperature = 1.0
	}
	if cfg.MaxTokens <= 0 {
		cfg.MaxTokens = 8192
	}
	if cfg.CircuitBreakerMaxCallsPerMinute <= 0 {
		cfg.CircuitBreakerMaxCallsPerMinute = 30
	}

	appMap := make(map[string]bool)
	for _, m := range cfg.ApprovedModels {
		appMap[strings.ToLower(strings.TrimSpace(m))] = true
	}

	s := &Server{
		config:         cfg,
		approvedMap:    appMap,
		redactor:       NewRedactor(),
		circuitBreaker: NewCircuitBreaker(cfg.CircuitBreakerMaxCallsPerMinute),
		client:         &http.Client{Timeout: 60 * time.Second},
		mux:            http.NewServeMux(),
	}

	s.setupRoutes()
	return s
}

// Routes returns the HTTP handler for mounting the gateway proxy.
func (s *Server) Routes() http.Handler {
	return s.mux
}

func (s *Server) setupRoutes() {
	s.mux.HandleFunc("/v1/chat/completions", s.handleChatCompletions)
	s.mux.HandleFunc("/v1/messages", s.handleAnthropicMessages)
	s.mux.HandleFunc("/v1/mcp/invoke", s.handleMCPInvoke)
	s.mux.HandleFunc("/healthz", s.handleHealthz)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":    "healthy",
		"service":   "airom-runtime-gateway",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

type chatCompletionPayload struct {
	Model       string                   `json:"model"`
	Messages    []map[string]interface{} `json:"messages"`
	Temperature *float64                 `json:"temperature,omitempty"`
	MaxTokens   *int                     `json:"max_tokens,omitempty"`
}

func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.Header.Get("Authorization")
	}

	// 1. Check Circuit Breaker for Runaway Loops
	allowed, count := s.circuitBreaker.Allow(sessionID)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Circuit breaker tripped: runaway agentic loop detected (%d calls/min exceeds threshold)", count),
			"code":  "CIRCUIT_BREAKER_TRIPPED",
		})
		return
	}

	// 2. Read Request Body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}
	_ = r.Body.Close()

	var payload chatCompletionPayload
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	// 3. Model Whitelisting Policy
	modelName := strings.ToLower(strings.TrimSpace(payload.Model))
	s.mu.RLock()
	isApproved := modelName != "" && (len(s.approvedMap) == 0 || s.approvedMap[modelName])
	s.mu.RUnlock()

	if !isApproved {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Access Denied: Model %q is not in the approved corporate AI catalog (.airomapproved)", payload.Model),
			"code":  "UNAPPROVED_MODEL_BLOCKED",
		})
		return
	}

	// 4. Parameter Clamping Policy
	if payload.Temperature != nil {
		if *payload.Temperature > s.config.MaxTemperature {
			clamped := s.config.MaxTemperature
			payload.Temperature = &clamped
		} else if *payload.Temperature < 0.0 {
			minTemp := 0.0
			payload.Temperature = &minTemp
		}
	}
	if payload.MaxTokens != nil {
		if *payload.MaxTokens > s.config.MaxTokens {
			clamped := s.config.MaxTokens
			payload.MaxTokens = &clamped
		} else if *payload.MaxTokens < 1 {
			minTokens := 1
			payload.MaxTokens = &minTokens
		}
	}

	// 5. PII & Secret Redaction
	if s.config.EnableRedaction {
		for i := range payload.Messages {
			if contentStr, ok := payload.Messages[i]["content"].(string); ok {
				payload.Messages[i]["content"] = s.redactor.RedactText(contentStr)
			} else if contentSlice, ok := payload.Messages[i]["content"].([]interface{}); ok {
				for j := range contentSlice {
					if block, ok := contentSlice[j].(map[string]interface{}); ok {
						if textVal, ok := block["text"].(string); ok {
							block["text"] = s.redactor.RedactText(textVal)
						}
					}
				}
			}
		}
	}

	// 6. Upstream Forwarding or Direct Mock Response
	if s.config.UpstreamURL == "" {
		// Mock local gateway response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "chatcmpl-gateway-verified",
			"object":  "chat.completion",
			"created": time.Now().UTC().Unix(),
			"model":   payload.Model,
			"choices": []map[string]interface{}{
				{
					"index": 0,
					"message": map[string]interface{}{
						"role":    "assistant",
						"content": "AIROM Gateway Verified Response",
					},
					"finish_reason": "stop",
				},
			},
		})
		return
	}

	// Forward to upstream
	forwardBytes, _ := json.Marshal(payload)
	upstreamReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, s.config.UpstreamURL+"/v1/chat/completions", bytes.NewReader(forwardBytes))
	if err != nil {
		http.Error(w, "Failed to create upstream request", http.StatusInternalServerError)
		return
	}

	for k, vv := range r.Header {
		for _, v := range vv {
			upstreamReq.Header.Add(k, v)
		}
	}

	resp, err := s.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("Upstream gateway error: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (s *Server) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	// Anthropic messages endpoint delegation
	s.handleChatCompletions(w, r)
}

type mcpInvokePayload struct {
	ToolName  string                 `json:"tool_name"`
	Arguments map[string]interface{} `json:"arguments"`
}

func (s *Server) handleMCPInvoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.Header.Get("X-Session-ID")
	allowed, count := s.circuitBreaker.Allow(sessionID)
	if !allowed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"error": fmt.Sprintf("Circuit breaker tripped: recursive MCP tool invocations halted (%d calls/min)", count),
			"code":  "MCP_RECURSIVE_LOOP_HALTED",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "executed",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
