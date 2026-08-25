package marketplace

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// Meter coordinates cloud marketplace billing usage telemetry and batching.
type Meter struct {
	mu         sync.RWMutex
	seenTokens map[string]bool
	buffers    map[Provider][]UsageRecord
	totals     map[string]map[Dimension]int64 // Key: customerID -> Dimension -> Total
}

// NewMeter constructs a new cloud marketplace usage meter.
func NewMeter() *Meter {
	return &Meter{
		seenTokens: make(map[string]bool),
		buffers:    make(map[Provider][]UsageRecord),
		totals:     make(map[string]map[Dimension]int64),
	}
}

// IngestUsage processes and deduplicates a commercial usage event.
func (m *Meter) IngestUsage(provider Provider, customerID string, dim Dimension, qty int64, idempotencyToken string) (*UsageRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if qty <= 0 {
		return nil, fmt.Errorf("usage quantity must be positive, got %d", qty)
	}

	if idempotencyToken != "" {
		if m.seenTokens[idempotencyToken] {
			return nil, fmt.Errorf("duplicate usage token %s dropped", idempotencyToken)
		}
		m.seenTokens[idempotencyToken] = true
	}

	now := time.Now().UTC()
	h := sha256.Sum256([]byte(fmt.Sprintf("%s-%s-%s-%d", customerID, dim, idempotencyToken, now.UnixNano())))
	recordID := fmt.Sprintf("use-%s", hex.EncodeToString(h[:6]))

	rec := UsageRecord{
		RecordID:         recordID,
		CustomerID:       customerID,
		Provider:         provider,
		Dimension:        dim,
		Quantity:         qty,
		IdempotencyToken: idempotencyToken,
		Timestamp:        now,
	}

	m.buffers[provider] = append(m.buffers[provider], rec)

	if m.totals[customerID] == nil {
		m.totals[customerID] = make(map[Dimension]int64)
	}
	m.totals[customerID][dim] += qty

	return &rec, nil
}

// FlushBatch prepares and extracts a cloud marketplace delivery batch.
func (m *Meter) FlushBatch(provider Provider) *MeteringBatch {
	m.mu.Lock()
	defer m.mu.Unlock()

	records := m.buffers[provider]
	if len(records) == 0 {
		return nil
	}

	now := time.Now().UTC()
	var totalUnits int64
	for _, r := range records {
		totalUnits += r.Quantity
	}

	h := sha256.Sum256([]byte(string(provider) + now.Format(time.RFC3339Nano)))
	batchID := fmt.Sprintf("mbatch-%s", hex.EncodeToString(h[:6]))

	batch := &MeteringBatch{
		BatchID:      batchID,
		Provider:     provider,
		RecordCount:  len(records),
		TotalUnits:   totalUnits,
		Records:      records,
		DispatchedAt: now,
	}

	m.buffers[provider] = nil
	return batch
}

// ReconcileCustomer generates a billing summary report for a customer.
func (m *Meter) ReconcileCustomer(customerID string, provider Provider) ReconciliationReport {
	m.mu.RLock()
	defer m.mu.RUnlock()

	now := time.Now().UTC()
	totalsCopy := make(map[Dimension]int64)
	if custTotals, exists := m.totals[customerID]; exists {
		for k, v := range custTotals {
			totalsCopy[k] = v
		}
	}

	return ReconciliationReport{
		CustomerID:  customerID,
		Provider:    provider,
		Totals:      totalsCopy,
		GeneratedAt: now,
	}
}
