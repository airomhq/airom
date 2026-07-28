package airom

import (
	"encoding/json"
	"testing"
	"time"
)

// TestDateMarshalsAsACalendarDay is the reason this type exists: a retirement
// is announced as a day, and a time.Time would marshal 2026-08-05 as
// "2026-08-05T00:00:00Z" — which any consumer west of UTC renders as Aug 4.
func TestDateMarshalsAsACalendarDay(t *testing.T) {
	d := Date{Year: 2026, Month: time.August, Day: 5}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"2026-08-05"` {
		t.Errorf("Marshal = %s, want \"2026-08-05\"", b)
	}
	var back Date
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != d {
		t.Errorf("round-trip = %v, want %v", back, d)
	}
	if err := json.Unmarshal([]byte(`"2026-08-05T00:00:00Z"`), &back); err == nil {
		t.Error("a timestamp must not parse as a Date")
	}
}

// TestDateOfIsZoneStable: the same instant yields the same UTC day no matter
// which zone the caller's clock is in.
func TestDateOfIsZoneStable(t *testing.T) {
	instant := time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)
	ny, _ := time.LoadLocation("America/New_York")
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	want := Date{2026, time.August, 5}
	for _, loc := range []*time.Location{time.UTC, ny, tokyo} {
		if got := DateOf(instant.In(loc)); got != want {
			t.Errorf("DateOf(%s) = %v, want %v", instant.In(loc), got, want)
		}
	}
}

func TestDateArithmeticAndOrder(t *testing.T) {
	a := Date{2026, time.August, 5}
	b := Date{2026, time.August, 20}
	if got := a.DaysUntil(b); got != 15 {
		t.Errorf("DaysUntil = %d, want 15", got)
	}
	if got := b.DaysUntil(a); got != -15 {
		t.Errorf("reverse DaysUntil = %d, want -15", got)
	}
	if !a.Before(b) || !b.After(a) || !a.Equal(a) {
		t.Error("ordering is wrong")
	}
	if got := a.AddDays(15); got != b {
		t.Errorf("AddDays = %v, want %v", got, b)
	}
	// Crossing a month and a leap day.
	if got := (Date{2028, time.February, 28}).AddDays(1); got != (Date{2028, time.February, 29}) {
		t.Errorf("leap day = %v", got)
	}
	if (Date{}).IsZero() != true {
		t.Error("zero Date must report IsZero")
	}
}

func TestParseDateStrict(t *testing.T) {
	if _, err := ParseDate("2026-08-05"); err != nil {
		t.Errorf("valid day rejected: %v", err)
	}
	for _, bad := range []string{"", "2026-13-01", "05-08-2026", "2026/08/05", "2026-08-05T00:00:00Z", "tomorrow"} {
		if _, err := ParseDate(bad); err == nil {
			t.Errorf("ParseDate(%q) should fail", bad)
		}
	}
}
