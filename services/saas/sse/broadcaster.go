package sse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Broadcaster manages tenant-scoped real-time SSE event publishing.
type Broadcaster struct {
	mu      sync.RWMutex
	clients map[string]*Client            // Key: clientID
	byOrg   map[string]map[string]*Client // Key: orgID -> map[clientID]*Client
	bufSize int
}

// NewBroadcaster constructs a new real-time SSE broadcaster.
func NewBroadcaster(bufferSize int) *Broadcaster {
	if bufferSize <= 0 {
		bufferSize = 100
	}
	return &Broadcaster{
		clients: make(map[string]*Client),
		byOrg:   make(map[string]map[string]*Client),
		bufSize: bufferSize,
	}
}

// Subscribe registers a new SSE listener for an organization.
func (b *Broadcaster) Subscribe(clientID, orgID string) *Client {
	b.mu.Lock()
	defer b.mu.Unlock()

	client := &Client{
		ID:      clientID,
		OrgID:   orgID,
		Channel: make(chan Message, b.bufSize),
	}

	b.clients[clientID] = client
	if b.byOrg[orgID] == nil {
		b.byOrg[orgID] = make(map[string]*Client)
	}
	b.byOrg[orgID][clientID] = client
	return client
}

// Unsubscribe removes a client and closes its channel.
func (b *Broadcaster) Unsubscribe(clientID string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	client, exists := b.clients[clientID]
	if !exists {
		return
	}

	delete(b.clients, clientID)
	if orgClients, ok := b.byOrg[client.OrgID]; ok {
		delete(orgClients, clientID)
		if len(orgClients) == 0 {
			delete(b.byOrg, client.OrgID)
		}
	}
	close(client.Channel)
}

// Publish broadcasts an event to all connected listeners within the target organization.
func (b *Broadcaster) Publish(orgID string, eventType EventType, payload string) *Message {
	b.mu.RLock()
	defer b.mu.RUnlock()

	now := time.Now().UTC()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%d", orgID, eventType, now.UnixNano())))
	msg := Message{
		ID:        fmt.Sprintf("msg-%s", hex.EncodeToString(h[:6])),
		OrgID:     orgID,
		Type:      eventType,
		Payload:   payload,
		Timestamp: now,
	}

	orgClients, exists := b.byOrg[orgID]
	if !exists {
		return &msg
	}

	for _, client := range orgClients {
		select {
		case client.Channel <- msg:
		default:
			// Non-blocking drop on slow reader to prevent backpressure cascade
		}
	}

	return &msg
}

// ClientCount returns active connected client count.
func (b *Broadcaster) ClientCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.clients)
}
