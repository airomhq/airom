package marketplace

import (
	"testing"
)

func TestQA_AdversarialZeroAndNegativeUsage(t *testing.T) {
	meter := NewMeter()

	_, err := meter.IngestUsage(ProviderAWS, "cust-1", DimensionModelScans, 0, "")
	if err == nil {
		t.Fatalf("expected error on zero quantity")
	}

	_, err = meter.IngestUsage(ProviderAWS, "cust-1", DimensionModelScans, -100, "")
	if err == nil {
		t.Fatalf("expected error on negative quantity")
	}
}

func TestQA_AdversarialEmptyCustomerID(t *testing.T) {
	meter := NewMeter()
	rec, err := meter.IngestUsage(ProviderGCP, "", DimensionStorageGB, 50, "")
	if err != nil || rec == nil {
		t.Fatalf("expected valid record on empty customer ID: %v", err)
	}
}
