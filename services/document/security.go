package document

import (
	"crypto/hmac"
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
	DefaultHumanTokenTTL = 90 * time.Second
)

var (
	ErrTokenExpired      = errors.New("human confirmation token has expired (TTL = 90s)")
	ErrTokenInvalidSig   = errors.New("human confirmation token signature is invalid or tampered")
	ErrTokenDocMismatch  = errors.New("human confirmation token is not authorized for this document")
	ErrTokenMalformed    = errors.New("malformed human confirmation token structure")
)

// GenerateHumanToken creates a signed, ephemeral 90-second confirmation token.
func GenerateHumanToken(secret []byte, req TokenRequest, ttl time.Duration) (string, HumanToken, error) {
	if len(secret) == 0 {
		return "", HumanToken{}, errors.New("HMAC secret key cannot be empty")
	}
	if req.DocumentID == "" {
		return "", HumanToken{}, errors.New("document_id is required to issue human token")
	}
	if req.UserID == "" {
		return "", HumanToken{}, errors.New("user_id is required to issue human token")
	}
	if ttl <= 0 {
		ttl = DefaultHumanTokenTTL
	}

	now := time.Now().UTC()
	tokenID := fmt.Sprintf("tok-%d", now.UnixNano())
	token := HumanToken{
		TokenID:    tokenID,
		UserID:     req.UserID,
		UserEmail:  req.UserEmail,
		DocumentID: req.DocumentID,
		IssuedAt:   now,
		ExpiresAt:  now.Add(ttl),
	}

	payloadJSON, err := json.Marshal(token)
	if err != nil {
		return "", HumanToken{}, fmt.Errorf("failed to serialize token payload: %w", err)
	}

	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := hex.EncodeToString(mac.Sum(nil))

	tokenString := fmt.Sprintf("%s.%s", payloadB64, sig)
	return tokenString, token, nil
}

// VerifyHumanToken validates an ephemeral confirmation token against a document ID.
func VerifyHumanToken(secret []byte, tokenString, expectedDocID string) (*HumanToken, error) {
	if len(secret) == 0 {
		return nil, errors.New("HMAC secret key cannot be empty")
	}
	if tokenString == "" {
		return nil, errors.New("missing human confirmation token")
	}

	parts := strings.Split(tokenString, ".")
	if len(parts) != 2 {
		return nil, ErrTokenMalformed
	}

	payloadB64 := parts[0]
	providedSig := parts[1]

	// 1. Verify HMAC Signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(providedSig), []byte(expectedSig)) {
		return nil, ErrTokenInvalidSig
	}

	// 2. Decode Token Payload
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, ErrTokenMalformed
	}

	var token HumanToken
	if err := json.NewDecoder(strings.NewReader(string(payloadBytes))).Decode(&token); err != nil {
		return nil, ErrTokenMalformed
	}

	// 3. Verify Document Scoping
	if expectedDocID != "" && token.DocumentID != expectedDocID {
		return nil, fmt.Errorf("%w: token doc=%q, requested doc=%q", ErrTokenDocMismatch, token.DocumentID, expectedDocID)
	}

	// 4. Verify Expiration Time
	if time.Now().UTC().After(token.ExpiresAt) {
		return nil, fmt.Errorf("%w: expired at %s", ErrTokenExpired, token.ExpiresAt.Format(time.RFC3339))
	}

	return &token, nil
}
