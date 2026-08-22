package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// EventType defines the category of an SSE event.
type EventType string

const (
	EventAnomalyDetected   EventType = "anomaly_detected"
	EventSnapshotCommitted EventType = "snapshot_committed"
	EventAttestationSigned EventType = "attestation_signed"
	EventQuotaAlert        EventType = "quota_alert"
	EventHeartbeat         EventType = "heartbeat"
)

// ServerEvent represents a real-time event dispatched to connected SSE clients.
type ServerEvent struct {
	ID        string      `json:"id"`
	Type      EventType   `json:"type"`
	Timestamp string      `json:"timestamp"`
	Data      interface{} `json:"data"`
}

// EventBroker manages active SSE client connections and broadcasts events.
type EventBroker struct {
	mu        sync.RWMutex
	clients   map[chan ServerEvent]bool
	broadcast chan ServerEvent
}

// NewEventBroker initializes a thread-safe event broker.
func NewEventBroker() *EventBroker {
	b := &EventBroker{
		clients:   make(map[chan ServerEvent]bool),
		broadcast: make(chan ServerEvent, 256),
	}
	go b.run()
	return b
}

func (b *EventBroker) run() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case ev := <-b.broadcast:
			b.mu.RLock()
			for ch := range b.clients {
				select {
				case ch <- ev:
				default:
					// Drop if client buffer is congested
				}
			}
			b.mu.RUnlock()
		case <-ticker.C:
			// Send heartbeat to keep HTTP connections alive
			b.Broadcast(ServerEvent{
				ID:        fmt.Sprintf("hb_%d", time.Now().Unix()),
				Type:      EventHeartbeat,
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Data:      map[string]string{"status": "alive"},
			})
		}
	}
}

// Broadcast sends an event to all subscribed clients.
func (b *EventBroker) Broadcast(ev ServerEvent) {
	if ev.Timestamp == "" {
		ev.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	b.broadcast <- ev
}

// Subscribe registers a new client channel.
func (b *EventBroker) Subscribe() chan ServerEvent {
	ch := make(chan ServerEvent, 32)
	b.mu.Lock()
	b.clients[ch] = true
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes an inactive client channel.
func (b *EventBroker) Unsubscribe(ch chan ServerEvent) {
	b.mu.Lock()
	if _, ok := b.clients[ch]; ok {
		delete(b.clients, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// ClientCount returns the number of active SSE subscribers.
func (b *EventBroker) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}

// Handler returns an HTTP handler for Server-Sent Events.
func (b *EventBroker) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Access-Control-Allow-Origin", "*")

		ch := b.Subscribe()
		defer b.Unsubscribe(ch)

		// Send initial connect handshake
		initEv := ServerEvent{
			ID:        "init",
			Type:      EventHeartbeat,
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      map[string]string{"message": "Connected to AIROM Enterprise Event Stream"},
		}
		data, _ := json.Marshal(initEv.Data)
		fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", initEv.ID, initEv.Type, string(data))
		flusher.Flush()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-ch:
				if !ok {
					return
				}
				evData, err := json.Marshal(ev.Data)
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "id: %s\nevent: %s\ndata: %s\n\n", ev.ID, ev.Type, string(evData))
				flusher.Flush()
			}
		}
	}
}
