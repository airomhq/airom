package calendar

import (
	"testing"
	"time"
)

func TestCalendar_ComputeActionNotices(t *testing.T) {
	pipeline := NewPipeline()

	// Evaluate as of June 1, 2026
	refTime := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	notices := pipeline.ComputeActionNotices(refTime)

	if len(notices) != 3 {
		t.Fatalf("expected 3 notices, got %d", len(notices))
	}

	// 1st notice should be California (overdue as of June 2026 since deadline was Jan 1, 2026)
	if !notices[0].IsOverdue || notices[0].Jurisdiction != "California" {
		t.Errorf("expected California to be earliest/overdue notice, got: %+v", notices[0])
	}

	// EU AI Act should have around 62 days remaining (Aug 2, 2026)
	for _, n := range notices {
		if n.Jurisdiction == "European Union" {
			if n.DaysRemaining < 60 || n.DaysRemaining > 65 {
				t.Errorf("expected ~62 days for EU AI Act, got %d", n.DaysRemaining)
			}
			if n.Urgency != "UPCOMING_DEADLINE" {
				t.Errorf("expected UPCOMING_DEADLINE, got %s", n.Urgency)
			}
		}
	}
}

func TestCalendar_EmptyPipeline(t *testing.T) {
	pipeline := &Pipeline{}
	notices := pipeline.ComputeActionNotices(time.Now())
	if len(notices) != 0 {
		t.Errorf("expected 0 notices on empty pipeline")
	}
}
