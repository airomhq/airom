package marketplace

import (
	"testing"
)

func TestMarketplace_IngestAndFlushBatch(t *testing.T) {
	meter := NewMeter()

	_, err := meter.IngestUsage(ProviderAWS, "cust-1", DimensionModelScans, 10, "tok-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = meter.IngestUsage(ProviderAWS, "cust-1", DimensionAgentSeats, 5, "tok-2")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	batch := meter.FlushBatch(ProviderAWS)
	if batch == nil || batch.RecordCount != 2 || batch.TotalUnits != 15 {
		t.Fatalf("expected batch with 2 records and 15 units, got: %+v", batch)
	}

	report := meter.ReconcileCustomer("cust-1", ProviderAWS)
	if report.Totals[DimensionModelScans] != 10 || report.Totals[DimensionAgentSeats] != 5 {
		t.Errorf("unexpected customer reconciliation totals: %+v", report.Totals)
	}
}

func TestMarketplace_IdempotencyDeduplication(t *testing.T) {
	meter := NewMeter()

	_, err := meter.IngestUsage(ProviderAzure, "cust-2", DimensionModelScans, 1, "token-duplicate")
	if err != nil {
		t.Fatalf("first ingestion should succeed: %v", err)
	}

	_, err = meter.IngestUsage(ProviderAzure, "cust-2", DimensionModelScans, 1, "token-duplicate")
	if err == nil {
		t.Fatalf("expected duplicate token error on re-submission")
	}
}
