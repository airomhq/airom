package calendar

import (
	"testing"
	"time"
)

func TestQA_AdversarialExtremeDates(t *testing.T) {
	pipeline := NewPipeline()

	// Milestone in year 3000
	pipeline.RegisterMilestone(StatutoryMilestone{
		MilestoneID:  "FUTURE-3000",
		Jurisdiction: "Global",
		DeadlineDate: time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	// Milestone in year 1900
	pipeline.RegisterMilestone(StatutoryMilestone{
		MilestoneID:  "PAST-1900",
		Jurisdiction: "Global",
		DeadlineDate: time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
	})

	notices := pipeline.ComputeActionNotices(time.Now())
	if len(notices) != 5 {
		t.Fatalf("expected 5 notices, got %d", len(notices))
	}
}

func TestQA_AdversarialDuplicateMilestoneIDs(t *testing.T) {
	pipeline := NewPipeline()
	m := StatutoryMilestone{
		MilestoneID:  "DUP-1",
		Jurisdiction: "Test",
		DeadlineDate: time.Now().Add(24 * time.Hour),
	}
	pipeline.RegisterMilestone(m)
	pipeline.RegisterMilestone(m)

	notices := pipeline.ComputeActionNotices(time.Now())
	if len(notices) != 5 {
		t.Fatalf("expected 5 total notices with duplicates appended")
	}
}
