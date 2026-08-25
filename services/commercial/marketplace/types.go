// Package marketplace coordinates commercial cloud marketplace metering,
// usage telemetry, and billing reconciliation for AWS Marketplace, Azure Marketplace, and GCP Marketplace.
package marketplace

import (
	"time"
)

// Provider identifies the cloud marketplace vendor.
type Provider string

const (
	ProviderAWS   Provider = "AWS_MARKETPLACE"
	ProviderAzure Provider = "AZURE_MARKETPLACE"
	ProviderGCP   Provider = "GCP_MARKETPLACE"
)

// Dimension defines a billable commercial metering unit.
type Dimension string

const (
	DimensionModelScans  Dimension = "DIMENSION_MODEL_SCANS"
	DimensionAgentSeats  Dimension = "DIMENSION_AGENT_SEATS"
	DimensionStorageGB   Dimension = "DIMENSION_STORAGE_GB"
	DimensionRedTeamRuns Dimension = "DIMENSION_RED_TEAM_RUNS"
)

// UsageRecord represents an individual metered customer consumption event.
type UsageRecord struct {
	RecordID         string    `json:"recordId"`
	CustomerID       string    `json:"customerId"` // e.g. "aws-customer-12345"
	Provider         Provider  `json:"provider"`
	Dimension        Dimension `json:"dimension"`
	Quantity         int64     `json:"quantity"`
	IdempotencyToken string    `json:"idempotencyToken"`
	Timestamp        time.Time `json:"timestamp"`
}

// MeteringBatch aggregates multiple usage records ready for cloud marketplace API ingestion.
type MeteringBatch struct {
	BatchID      string        `json:"batchId"`
	Provider     Provider      `json:"provider"`
	RecordCount  int           `json:"recordCount"`
	TotalUnits   int64         `json:"totalUnits"`
	Records      []UsageRecord `json:"records"`
	DispatchedAt time.Time     `json:"dispatchedAt"`
}

// ReconciliationReport summarizes customer billing totals across all dimensions.
type ReconciliationReport struct {
	CustomerID  string              `json:"customerId"`
	Provider    Provider            `json:"provider"`
	Totals      map[Dimension]int64 `json:"totals"`
	GeneratedAt time.Time           `json:"generatedAt"`
}
