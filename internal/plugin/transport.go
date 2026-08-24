package plugin

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Transport manages framed message transmission between host and plugin.
type Transport struct {
	secretKey string
	handlers  map[string]func(req PluginMessage) PluginMessage
	mu        sync.RWMutex
}

// NewTransport constructs an in-memory / loopback IPC transport.
func NewTransport(secretKey string) *Transport {
	return &Transport{
		secretKey: secretKey,
		handlers:  make(map[string]func(req PluginMessage) PluginMessage),
	}
}

// ComputeAuthHMAC generates an HMAC-SHA256 authentication token.
func (t *Transport) ComputeAuthHMAC(token string, ts time.Time) string {
	mac := hmac.New(sha256.New, []byte(t.secretKey))
	mac.Write([]byte(fmt.Sprintf("%s:%d", token, ts.Unix())))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyHandshake authenticates a HandshakeRequest.
func (t *Transport) VerifyHandshake(req HandshakeRequest) error {
	if req.ProtocolVersion != ProtocolVersion {
		return fmt.Errorf("%w: protocol version mismatch %s != %s", ErrHandshakeFailed, req.ProtocolVersion, ProtocolVersion)
	}
	if req.MagicToken != MagicHandshakeToken {
		return fmt.Errorf("%w: invalid magic token", ErrHandshakeFailed)
	}

	expectedHMAC := t.ComputeAuthHMAC(req.MagicToken, req.Timestamp)
	if req.AuthHMAC != expectedHMAC {
		return fmt.Errorf("%w: HMAC signature mismatch", ErrHandshakeFailed)
	}

	return nil
}

// RegisterMethod registers an RPC method handler.
func (t *Transport) RegisterMethod(method string, handler func(req PluginMessage) PluginMessage) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.handlers[method] = handler
}

// Call executes an RPC invocation.
func (t *Transport) Call(msg PluginMessage) (PluginMessage, error) {
	t.mu.RLock()
	handler, exists := t.handlers[msg.Method]
	t.mu.RUnlock()

	if !exists {
		return PluginMessage{
			ID:        msg.ID,
			IsError:   true,
			ErrorText: fmt.Sprintf("unregistered method: %s", msg.Method),
		}, fmt.Errorf("method not found: %s", msg.Method)
	}

	resp := handler(msg)
	return resp, nil
}

// EncodeJSON helper.
func EncodeJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
