package server

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEventBroker_BroadcastAndSubscribe(t *testing.T) {
	broker := NewEventBroker()

	ch1 := broker.Subscribe()
	ch2 := broker.Subscribe()

	if broker.ClientCount() != 2 {
		t.Fatalf("expected 2 clients, got %d", broker.ClientCount())
	}

	testEv := ServerEvent{
		ID:   "ev_101",
		Type: EventAnomalyDetected,
		Data: map[string]string{
			"repo":      "acme/test-repo",
			"component": "pkg:pypi/openai@1.51.0",
		},
	}

	broker.Broadcast(testEv)

	// Verify client 1 received
	select {
	case received := <-ch1:
		if received.ID != "ev_101" || received.Type != EventAnomalyDetected {
			t.Fatalf("client 1 received unexpected event: %+v", received)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for event on client 1")
	}

	// Verify client 2 received
	select {
	case received := <-ch2:
		if received.ID != "ev_101" {
			t.Fatalf("client 2 received unexpected event: %+v", received)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for event on client 2")
	}

	broker.Unsubscribe(ch1)
	broker.Unsubscribe(ch2)

	if broker.ClientCount() != 0 {
		t.Fatalf("expected 0 clients after unsubscribe, got %d", broker.ClientCount())
	}
}

func TestEventBroker_HTTPHandlerStream(t *testing.T) {
	broker := NewEventBroker()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest("GET", "/api/v1/events/stream", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		broker.Handler().ServeHTTP(rec, req)
		close(done)
	}()

	// Allow goroutine to establish subscription
	time.Sleep(50 * time.Millisecond)

	broker.Broadcast(ServerEvent{
		ID:   "ev_anomaly_01",
		Type: EventAnomalyDetected,
		Data: map[string]string{"type": "shadow-ai"},
	})

	// Allow frame to be written and flushed
	time.Sleep(100 * time.Millisecond)
	cancel()
	<-done

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "text/event-stream") {
		t.Fatalf("expected Content-Type text/event-stream, got %s", contentType)
	}

	body := rec.Body.String()
	scanner := bufio.NewScanner(strings.NewReader(body))
	var foundInit, foundAnomaly bool

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Connected to AIROM Enterprise Event Stream") {
			foundInit = true
		}
		if strings.Contains(line, "ev_anomaly_01") {
			foundAnomaly = true
		}
	}

	if !foundInit {
		t.Error("did not find initial handshake event in stream output")
	}
	if !foundAnomaly {
		t.Error("did not find broadcasted anomaly event in stream output")
	}
}
