package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultSessionTTL = 24 * time.Hour
	APIKeyPrefix      = "airom_live_"
)

var (
	ErrTokenExpired    = errors.New("auth token has expired")
	ErrTokenInvalidSig = errors.New("auth token signature is invalid or tampered")
	ErrTokenMalformed  = errors.New("malformed auth token structure")
	ErrKeyInactive     = errors.New("api key has been revoked or is inactive")
	ErrKeyExpired      = errors.New("api key has expired")
)

// IssueSessionToken mints a cryptographically signed session token for a user.
func IssueSessionToken(secret []byte, user User, ttl time.Duration) (string, AuthClaims, error) {
	if len(secret) == 0 {
		return "", AuthClaims{}, errors.New("secret key cannot be empty")
	}
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}

	now := time.Now().UTC()
	claims := AuthClaims{
		UserID:      user.ID,
		OrgID:       user.OrgID,
		Email:       user.Email,
		Role:        user.Role,
		Permissions: GetRolePermissions(user.Role),
		TokenType:   "user_session",
		IssuedAt:    now,
		ExpiresAt:   now.Add(ttl),
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", AuthClaims{}, fmt.Errorf("failed to encode claims: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := hex.EncodeToString(mac.Sum(nil))

	tokenStr := fmt.Sprintf("%s.%s", payloadB64, sig)
	return tokenStr, claims, nil
}

// VerifySessionToken parses and validates a session token.
func VerifySessionToken(secret []byte, tokenStr string) (*AuthClaims, error) {
	if len(secret) == 0 {
		return nil, errors.New("secret key cannot be empty")
	}
	if strings.TrimSpace(tokenStr) == "" {
		return nil, errors.New("missing auth token")
	}

	parts := strings.Split(tokenStr, ".")
	if len(parts) != 2 {
		return nil, ErrTokenMalformed
	}

	payloadB64 := parts[0]
	providedSig := parts[1]

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return nil, ErrTokenInvalidSig
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	var claims AuthClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, ErrTokenMalformed
	}

	if time.Now().UTC().After(claims.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired at %s", ErrTokenExpired, claims.ExpiresAt.Format(time.RFC3339))
	}

	return &claims, nil
}

// MintAPIKey generates a cryptographically secure random API key.
func MintAPIKey(orgID, name string, role Role, customPerms []Permission) (string, APIKey, error) {
	if orgID == "" {
		return "", APIKey{}, errors.New("org_id is required")
	}
	if name == "" {
		name = "Default API Key"
	}
	if err := ValidateRole(role); err != nil {
		role = RoleDeveloper
	}

	perms := customPerms
	if len(perms) == 0 {
		perms = GetRolePermissions(role)
	}

	randomBytes := make([]byte, 24)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", APIKey{}, fmt.Errorf("failed to generate random entropy: %w", err)
	}

	entropyHex := hex.EncodeToString(randomBytes)
	rawKey := fmt.Sprintf("%s%s", APIKeyPrefix, entropyHex)

	keyHashBytes := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(keyHashBytes[:])

	now := time.Now().UTC()
	keyID := fmt.Sprintf("key-%d-%s", now.UnixNano(), entropyHex[:8])
	prefix := rawKey[:18] + "..." // e.g. "airom_live_a1b2c3d..."

	apiKey := APIKey{
		ID:          keyID,
		OrgID:       orgID,
		KeyPrefix:   prefix,
		KeyHash:     keyHash,
		Name:        name,
		Role:        role,
		Permissions: perms,
		CreatedAt:   now,
		IsActive:    true,
	}

	return rawKey, apiKey, nil
}

// AuthenticateAPIKey verifies a raw API key against stored hashed keys.
func AuthenticateAPIKey(rawKey string, storedKeys []APIKey) (*APIKey, *AuthClaims, error) {
	if !strings.HasPrefix(rawKey, APIKeyPrefix) {
		return nil, nil, errors.New("invalid api key format")
	}

	rawHashBytes := sha256.Sum256([]byte(rawKey))
	rawHash := hex.EncodeToString(rawHashBytes[:])

	var matched *APIKey
	for _, k := range storedKeys {
		if k.KeyHash == rawHash {
			matched = &k
			break
		}
	}

	if matched == nil {
		return nil, nil, errors.New("invalid api key")
	}
	if !matched.IsActive {
		return nil, nil, ErrKeyInactive
	}
	if matched.ExpiresAt != nil && time.Now().UTC().After(*matched.ExpiresAt) {
		return nil, nil, ErrKeyExpired
	}

	now := time.Now().UTC()
	claims := AuthClaims{
		UserID:      matched.ID,
		OrgID:       matched.OrgID,
		Email:       fmt.Sprintf("apikey:%s", matched.Name),
		Role:        matched.Role,
		Permissions: matched.Permissions,
		TokenType:   "api_key",
		IssuedAt:    now,
		ExpiresAt:   now.Add(365 * 24 * time.Hour),
	}

	return matched, &claims, nil
}
