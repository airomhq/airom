package identity

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Attestor issues and verifies SPIFFE SVID credentials for AI agents.
type Attestor struct {
	trustDomain string
	secretKey   string
}

// NewAttestor constructs a SPIFFE agent identity attestor.
func NewAttestor(trustDomain, secretKey string) *Attestor {
	return &Attestor{
		trustDomain: trustDomain,
		secretKey:   secretKey,
	}
}

// FormatSPIFFEID constructs a canonical SPIFFE ID URI.
func (a *Attestor) FormatSPIFFEID(namespace, agentName string) string {
	return fmt.Sprintf("spiffe://%s/ns/%s/agent/%s", a.trustDomain, namespace, agentName)
}

// IssueSVID generates a signed SVID credential for an agent identity.
func (a *Attestor) IssueSVID(id AgentIdentity, ttl time.Duration) SVIDCredential {
	if ttl == 0 {
		ttl = 1 * time.Hour
	}

	issued := time.Now().UTC()
	expires := issued.Add(ttl)

	rawPayload := fmt.Sprintf("%s|%d|%d", id.SPIFFEID, issued.Unix(), expires.Unix())
	encodedPayload := base64.RawURLEncoding.EncodeToString([]byte(rawPayload))

	mac := hmac.New(sha256.New, []byte(a.secretKey))
	mac.Write([]byte(encodedPayload))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	token := fmt.Sprintf("%s.%s", encodedPayload, sigHex)

	return SVIDCredential{
		SPIFFEID:  id.SPIFFEID,
		Type:      SVIDTypeJWT,
		Token:     token,
		IssuedAt:  issued,
		ExpiresAt: expires,
	}
}

// VerifySVID cryptographically validates an incoming SVID token.
func (a *Attestor) VerifySVID(token string) (string, error) {
	lastDot := strings.LastIndex(token, ".")
	if lastDot == -1 {
		return "", fmt.Errorf("malformed SVID token format")
	}

	encodedPayload := token[:lastDot]
	sigHex := token[lastDot+1:]

	mac := hmac.New(sha256.New, []byte(a.secretKey))
	mac.Write([]byte(encodedPayload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sigHex), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid SVID cryptographic signature")
	}

	rawPayloadBytes, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return "", fmt.Errorf("failed to decode SVID payload: %w", err)
	}

	payloadParts := strings.Split(string(rawPayloadBytes), "|")
	if len(payloadParts) < 3 {
		return "", fmt.Errorf("invalid SVID payload metadata")
	}

	spiffeID := payloadParts[0]
	var expUnix int64
	_, err = fmt.Sscanf(payloadParts[2], "%d", &expUnix)
	if err != nil {
		return "", fmt.Errorf("invalid SVID expiration timestamp")
	}

	if time.Now().UTC().Unix() > expUnix {
		return "", fmt.Errorf("SVID token expired")
	}

	if !strings.HasPrefix(spiffeID, fmt.Sprintf("spiffe://%s/", a.trustDomain)) {
		return "", fmt.Errorf("SVID trust domain mismatch: %s", spiffeID)
	}

	return spiffeID, nil
}
