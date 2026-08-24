package plugin

import (
	"context"
	"testing"
)

func TestPlugin_HandshakeNegotiation(t *testing.T) {
	transport := NewTransport("test_secret_key_123")
	manifest := PluginManifest{
		ID:           "custom-security-scanner",
		Name:         "SecurityScanner",
		Version:      "v1.0.0",
		Capabilities: []PluginCapability{CapDetector, CapAuditor},
	}

	sup := NewSupervisor(manifest, transport)

	resp, err := sup.Start(context.Background())
	if err != nil {
		t.Fatalf("start failed: %v", err)
	}

	if resp.Status != "ready" {
		t.Errorf("expected ready status, got %s", resp.Status)
	}

	if len(resp.Capabilities) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(resp.Capabilities))
	}
}

func TestPlugin_PingAndHealthProbe(t *testing.T) {
	transport := NewTransport("secret")
	transport.RegisterMethod("system.ping", func(req PluginMessage) PluginMessage {
		return PluginMessage{ID: req.ID, Method: "system.ping", Payload: []byte("PONG")}
	})

	sup := NewSupervisor(PluginManifest{ID: "p1"}, transport)
	_, _ = sup.Start(context.Background())

	if err := sup.Ping(context.Background()); err != nil {
		t.Fatalf("ping failed: %v", err)
	}

	_ = sup.Stop()
	if err := sup.Ping(context.Background()); err != ErrPluginCrashed {
		t.Fatalf("expected ErrPluginCrashed after stop, got %v", err)
	}
}

func TestPlugin_SupervisorCrashRecovery(t *testing.T) {
	transport := NewTransport("secret")
	transport.RegisterMethod("system.ping", func(req PluginMessage) PluginMessage {
		return PluginMessage{ID: req.ID, Method: "system.ping", Payload: []byte("PONG")}
	})

	sup := NewSupervisor(PluginManifest{ID: "p1"}, transport)
	_, _ = sup.Start(context.Background())

	// Simulate unexpected process termination
	_ = sup.Stop()
	if sup.IsRunning() {
		t.Fatalf("expected stopped")
	}

	// Restart
	if err := sup.Restart(context.Background()); err != nil {
		t.Fatalf("restart failed: %v", err)
	}

	if !sup.IsRunning() {
		t.Fatalf("expected running after restart")
	}

	if sup.RestartCount() != 1 {
		t.Errorf("expected restart count 1, got %d", sup.RestartCount())
	}
}
