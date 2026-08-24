package plugin

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// Supervisor oversees the lifecycle and health of an out-of-process plugin.
type Supervisor struct {
	manifest     PluginManifest
	transport    *Transport
	isRunning    int32
	restartCount int64
	mu           sync.RWMutex
}

// NewSupervisor constructs a plugin supervisor.
func NewSupervisor(manifest PluginManifest, transport *Transport) *Supervisor {
	return &Supervisor{
		manifest:  manifest,
		transport: transport,
	}
}

// Start initiates the plugin session and executes handshake negotiation.
func (s *Supervisor) Start(ctx context.Context) (*HandshakeResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	req := HandshakeRequest{
		ProtocolVersion: ProtocolVersion,
		MagicToken:      MagicHandshakeToken,
		HostVersion:     "1.0.0",
		AuthHMAC:        s.transport.ComputeAuthHMAC(MagicHandshakeToken, now),
		Timestamp:       now,
	}

	if err := s.transport.VerifyHandshake(req); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	atomic.StoreInt32(&s.isRunning, 1)

	return &HandshakeResponse{
		ProtocolVersion: ProtocolVersion,
		PluginID:        s.manifest.ID,
		Capabilities:    s.manifest.Capabilities,
		Status:          "ready",
	}, nil
}

// Ping performs a liveness probe on the supervised plugin.
func (s *Supervisor) Ping(ctx context.Context) error {
	if atomic.LoadInt32(&s.isRunning) == 0 {
		return ErrPluginCrashed
	}

	resp, err := s.transport.Call(PluginMessage{
		ID:     "ping",
		Method: "system.ping",
	})
	if err != nil {
		return err
	}
	if resp.IsError {
		return fmt.Errorf("ping error: %s", resp.ErrorText)
	}
	return nil
}

// Restart simulates/executes an automatic restart upon crash.
func (s *Supervisor) Restart(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	atomic.StoreInt32(&s.isRunning, 0)
	atomic.AddInt64(&s.restartCount, 1)

	// Re-handshake
	now := time.Now().UTC()
	req := HandshakeRequest{
		ProtocolVersion: ProtocolVersion,
		MagicToken:      MagicHandshakeToken,
		HostVersion:     "1.0.0",
		AuthHMAC:        s.transport.ComputeAuthHMAC(MagicHandshakeToken, now),
		Timestamp:       now,
	}

	if err := s.transport.VerifyHandshake(req); err != nil {
		return fmt.Errorf("restart handshake failed: %w", err)
	}

	atomic.StoreInt32(&s.isRunning, 1)
	return nil
}

// Stop terminates the plugin cleanly.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	atomic.StoreInt32(&s.isRunning, 0)
	return nil
}

// IsRunning returns true if the plugin is healthy and running.
func (s *Supervisor) IsRunning() bool {
	return atomic.LoadInt32(&s.isRunning) == 1
}

// RestartCount returns the number of times the supervisor restarted the process.
func (s *Supervisor) RestartCount() int64 {
	return atomic.LoadInt64(&s.restartCount)
}
