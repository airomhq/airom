package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Service provides the enterprise authentication service.
type Service struct {
	mu         sync.RWMutex
	secret     []byte
	users      map[string]*User      // userID -> User
	usersByEmail map[string]*User    // email -> User
	apiKeys    map[string]*APIKey    // keyID -> APIKey
	ssoConfigs map[string]*SSOConfig // orgID -> SSOConfig
	auditLogs  []AuthEvent
}

// NewService creates a new enterprise Auth Service.
func NewService(secret []byte) *Service {
	if len(secret) == 0 {
		secret = []byte("airom-auth-enterprise-secret-key-32b")
	}
	return &Service{
		secret:       secret,
		users:        make(map[string]*User),
		usersByEmail: make(map[string]*User),
		apiKeys:      make(map[string]*APIKey),
		ssoConfigs:   make(map[string]*SSOConfig),
		auditLogs:    make([]AuthEvent, 0),
	}
}

// Routes configures the HTTP routes.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/api/v1/auth/sso/callback", s.handleSSOCallback)
	mux.HandleFunc("/api/v1/auth/keys", s.handleKeysCollection)
	mux.HandleFunc("/api/v1/auth/keys/", s.handleKeyItem)
	mux.HandleFunc("/api/v1/auth/users", s.handleUsersCollection)
	mux.HandleFunc("/api/v1/auth/users/", s.handleUserItem)
	mux.HandleFunc("/api/v1/auth/audit", s.handleAuditLogs)
	return mux
}

// Authenticate extracts claims from Authorization header (Bearer JWT or API Key).
func (s *Service) Authenticate(r *http.Request) (*AuthClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		// Check X-API-Key header fallback
		apiKeyHeader := r.Header.Get("X-API-Key")
		if apiKeyHeader != "" {
			return s.authAPIKey(apiKeyHeader)
		}
		return nil, ErrUnauthorized
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 {
		return nil, ErrUnauthorized
	}

	tokenType := strings.ToLower(parts[0])
	tokenValue := parts[1]

	if tokenType == "bearer" {
		if strings.HasPrefix(tokenValue, APIKeyPrefix) {
			return s.authAPIKey(tokenValue)
		}
		return VerifySessionToken(s.secret, tokenValue)
	} else if tokenType == "apikey" {
		return s.authAPIKey(tokenValue)
	}

	return nil, ErrUnauthorized
}

func (s *Service) authAPIKey(rawKey string) (*AuthClaims, error) {
	s.mu.RLock()
	var keys []APIKey
	for _, k := range s.apiKeys {
		keys = append(keys, *k)
	}
	s.mu.RUnlock()

	_, claims, err := AuthenticateAPIKey(rawKey, keys)
	return claims, err
}

// RequirePermission wraps a handler with RBAC permission enforcement.
func (s *Service) RequirePermission(perm Permission, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := s.Authenticate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		if err := Authorize(claims, perm); err != nil {
			s.recordEvent(claims.OrgID, claims.UserID, "UNAUTHORIZED_ACCESS", fmt.Sprintf("Failed permission check %q", perm))
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

func (s *Service) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"service": "airom-auth-service",
	})
}

// handleSSOCallback processes SAML2/OIDC assertion callbacks.
func (s *Service) handleSSOCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OrgID       string `json:"org_id"`
		Email       string `json:"email"`
		Name        string `json:"name"`
		SSOProvider string `json:"sso_provider"`
		Role        Role   `json:"role,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.OrgID == "" {
		http.Error(w, "email and org_id are required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	user, exists := s.usersByEmail[req.Email]
	now := time.Now().UTC()
	if !exists {
		role := req.Role
		if role == "" {
			role = RoleDeveloper
		}
		user = &User{
			ID:          fmt.Sprintf("usr-%d", now.UnixNano()),
			OrgID:       req.OrgID,
			Email:       req.Email,
			Name:        req.Name,
			Role:        role,
			SSOProvider: req.SSOProvider,
			CreatedAt:   now,
			LastLoginAt: &now,
			IsActive:    true,
		}
		s.users[user.ID] = user
		s.usersByEmail[user.Email] = user
	} else {
		user.LastLoginAt = &now
	}
	s.mu.Unlock()

	tokenStr, claims, err := IssueSessionToken(s.secret, *user, DefaultSessionTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.recordEvent(user.OrgID, user.ID, "SSO_LOGIN", fmt.Sprintf("User logged in via %s", req.SSOProvider))

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      tokenStr,
		"user":       user,
		"claims":     claims,
		"expires_at": claims.ExpiresAt,
	})
}

// handleKeysCollection handles POST (mint key) and GET (list keys).
func (s *Service) handleKeysCollection(w http.ResponseWriter, r *http.Request) {
	claims, err := s.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPost:
		if err := Authorize(claims, PermKeyRotate); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		var req struct {
			Name        string       `json:"name"`
			Role        Role         `json:"role"`
			Permissions []Permission `json:"permissions,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		rawKey, apiKey, err := MintAPIKey(claims.OrgID, req.Name, req.Role, req.Permissions)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		s.apiKeys[apiKey.ID] = &apiKey
		s.mu.Unlock()

		s.recordEvent(claims.OrgID, claims.UserID, "KEY_MINTED", fmt.Sprintf("Minted API key %q", apiKey.Name))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"raw_api_key": rawKey,
			"key_details": apiKey,
		})

	case http.MethodGet:
		s.mu.RLock()
		var orgKeys []APIKey
		for _, k := range s.apiKeys {
			if k.OrgID == claims.OrgID {
				orgKeys = append(orgKeys, *k)
			}
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgKeys)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleKeyItem handles DELETE /api/v1/auth/keys/{id} (revoke key).
func (s *Service) handleKeyItem(w http.ResponseWriter, r *http.Request) {
	claims, err := s.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 5 {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	keyID := parts[4]

	if r.Method == http.MethodDelete {
		if err := Authorize(claims, PermKeyRotate); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		s.mu.Lock()
		key, exists := s.apiKeys[keyID]
		if !exists || key.OrgID != claims.OrgID {
			s.mu.Unlock()
			http.Error(w, "api key not found", http.StatusNotFound)
			return
		}
		key.IsActive = false
		s.mu.Unlock()

		s.recordEvent(claims.OrgID, claims.UserID, "KEY_REVOKED", fmt.Sprintf("Revoked key %s", keyID))
		w.WriteHeader(http.StatusOK)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleUsersCollection handles POST (create user) and GET (list users).
func (s *Service) handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	claims, err := s.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	switch r.Method {
	case http.MethodPost:
		if err := Authorize(claims, PermUserManage); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		var req struct {
			Email string `json:"email"`
			Name  string `json:"name"`
			Role  Role   `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := ValidateRole(req.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		now := time.Now().UTC()
		user := &User{
			ID:        fmt.Sprintf("usr-%d", now.UnixNano()),
			OrgID:     claims.OrgID,
			Email:     req.Email,
			Name:      req.Name,
			Role:      req.Role,
			CreatedAt: now,
			IsActive:  true,
		}

		s.mu.Lock()
		s.users[user.ID] = user
		s.usersByEmail[user.Email] = user
		s.mu.Unlock()

		s.recordEvent(claims.OrgID, claims.UserID, "USER_CREATED", fmt.Sprintf("Provisioned user %s with role %s", user.Email, user.Role))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(user)

	case http.MethodGet:
		s.mu.RLock()
		var orgUsers []User
		for _, u := range s.users {
			if u.OrgID == claims.OrgID {
				orgUsers = append(orgUsers, *u)
			}
		}
		s.mu.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgUsers)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleUserItem handles PUT /api/v1/auth/users/{id}/role.
func (s *Service) handleUserItem(w http.ResponseWriter, r *http.Request) {
	claims, err := s.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 6 || parts[5] != "role" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	targetUserID := parts[4]

	if r.Method == http.MethodPut {
		if err := Authorize(claims, PermUserManage); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}

		var req struct {
			Role Role `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := ValidateRole(req.Role); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		s.mu.Lock()
		user, exists := s.users[targetUserID]
		if !exists || user.OrgID != claims.OrgID {
			s.mu.Unlock()
			http.Error(w, "user not found", http.StatusNotFound)
			return
		}
		user.Role = req.Role
		s.mu.Unlock()

		s.recordEvent(claims.OrgID, claims.UserID, "ROLE_CHANGED", fmt.Sprintf("Updated role for %s to %s", user.Email, user.Role))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(user)
		return
	}

	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
}

// handleAuditLogs streams auth events.
func (s *Service) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	claims, err := s.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := Authorize(claims, PermAuditRead); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	s.mu.RLock()
	var logs []AuthEvent
	for _, e := range s.auditLogs {
		if e.OrgID == claims.OrgID {
			logs = append(logs, e)
		}
	}
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func (s *Service) recordEvent(orgID, userID, eventType, details string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.auditLogs = append(s.auditLogs, AuthEvent{
		ID:        fmt.Sprintf("ev-%d", time.Now().UTC().UnixNano()),
		OrgID:     orgID,
		UserID:    userID,
		EventType: eventType,
		Details:   details,
		Timestamp: time.Now().UTC(),
	})
}
