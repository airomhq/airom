// Package plugin implements the out-of-process plugin wire protocol and process supervisor
// for AIROM extensibility (ARCHITECTURE.md §16 reserved slot 5).
package plugin

import (
	"errors"
	"time"
)

const (
	// ProtocolVersion is the wire protocol semver.
	ProtocolVersion = "1.0.0"
	// MagicHandshakeToken is the authentication handshake token.
	MagicHandshakeToken = "AIROM_PLUGIN_WIRE_PROTOCOL_V1"
)

var (
	// ErrHandshakeFailed is returned when protocol version or magic token mismatches.
	ErrHandshakeFailed = errors.New("plugin: handshake negotiation failed")
	// ErrPluginCrashed is returned when a supervised plugin process terminates unexpectedly.
	ErrPluginCrashed = errors.New("plugin: process terminated unexpectedly")
	// ErrPluginTimeout is returned when a plugin RPC exceeds its timeout deadline.
	ErrPluginTimeout = errors.New("plugin: RPC deadline exceeded")
)

// PluginCapability enumerates the interfaces a plugin can provide.
type PluginCapability string

const (
	CapDetector PluginCapability = "detector"
	CapWriter   PluginCapability = "writer"
	CapAuditor  PluginCapability = "auditor"
	CapSource   PluginCapability = "source"
)

// PluginManifest describes a plugin binary's identity and capabilities.
type PluginManifest struct {
	ID           string             `json:"id"`
	Name         string             `json:"name"`
	Version      string             `json:"version"`
	Capabilities []PluginCapability `json:"capabilities"`
	BinaryPath   string             `json:"binaryPath"`
	Environment  map[string]string  `json:"environment,omitempty"`
}

// HandshakeRequest is sent from the host scanner to the plugin upon process spawn.
type HandshakeRequest struct {
	ProtocolVersion string            `json:"protocolVersion"`
	MagicToken      string            `json:"magicToken"`
	HostVersion     string            `json:"hostVersion"`
	AuthHMAC        string            `json:"authHmac"`
	Timestamp       time.Time         `json:"timestamp"`
	Config          map[string]string `json:"config,omitempty"`
}

// HandshakeResponse is returned by the plugin acknowledging the session.
type HandshakeResponse struct {
	ProtocolVersion string             `json:"protocolVersion"`
	PluginID        string             `json:"pluginId"`
	Capabilities    []PluginCapability `json:"capabilities"`
	Status          string             `json:"status"` // ready | error
	ErrorMessage    string             `json:"errorMessage,omitempty"`
}

// PluginMessage represents a framed RPC payload over the IPC transport.
type PluginMessage struct {
	ID        string `json:"id"`
	Method    string `json:"method"`
	Payload   []byte `json:"payload"`
	IsError   bool   `json:"isError,omitempty"`
	ErrorText string `json:"errorText,omitempty"`
}
