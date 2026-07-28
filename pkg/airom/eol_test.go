package airom

import (
	"testing"
	"time"
)

func day(y int, m time.Month, d int) Date { return Date{Year: y, Month: m, Day: d} }

// TestDeriveEOLStateAcrossShutdown pins the one piece of logic that changes
// answer with the calendar: a curated "deprecated" record must become "retired"
// on its own shutdown date, without anyone re-editing the catalog. The boundary
// is inclusive — on the shutdown day the model is already gone.
func TestDeriveEOLStateAcrossShutdown(t *testing.T) {
	shutdown := day(2026, time.August, 5)
	cases := []struct {
		name      string
		announced EOLState
		shutdown  *Date
		at        Date
		want      EOLState
	}{
		{"day before shutdown", EOLDeprecated, &shutdown, day(2026, time.August, 4), EOLDeprecated},
		{"on shutdown day", EOLDeprecated, &shutdown, day(2026, time.August, 5), EOLRetired},
		{"day after shutdown", EOLDeprecated, &shutdown, day(2026, time.August, 6), EOLRetired},
		{"long after", EOLDeprecated, &shutdown, day(2030, time.January, 1), EOLRetired},
		// A future shutdown date outranks a stale "supported" in the record.
		{"dated but marked supported", EOLSupported, &shutdown, day(2026, time.July, 1), EOLDeprecated},
		// No date: the announced state stands.
		{"deprecated, no date", EOLDeprecated, nil, day(2026, time.July, 1), EOLDeprecated},
		{"supported, no date", EOLSupported, nil, day(2026, time.July, 1), EOLSupported},
		{"retired, no date", EOLRetired, nil, day(2026, time.July, 1), EOLRetired},
		{"garbage state", EOLState("bogus"), nil, day(2026, time.July, 1), EOLUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveEOLState(tc.announced, tc.shutdown, tc.at); got != tc.want {
				t.Errorf("DeriveEOLState(%q, %v, %s) = %q, want %q",
					tc.announced, tc.shutdown, tc.at, got, tc.want)
			}
		})
	}
}

func TestDaysUntil(t *testing.T) {
	cases := []struct {
		shutdown, at Date
		want         int
	}{
		{day(2026, time.August, 5), day(2026, time.July, 23), 13},
		{day(2026, time.July, 23), day(2026, time.July, 23), 0},   // today
		{day(2025, time.June, 6), day(2026, time.July, 23), -412}, // already gone
	}
	for _, c := range cases {
		if got := c.at.DaysUntil(c.shutdown); got != c.want {
			t.Errorf("%s.DaysUntil(%s) = %d, want %d", c.at, c.shutdown, got, c.want)
		}
	}
	// The B1 invariant: state and DaysRemaining are computed from the SAME
	// calendar-day clock, so they can never contradict each other — whatever
	// zone the caller's instant came from. A "retired" state must always pair
	// with DaysRemaining <= 0.
	shutdown := day(2026, time.July, 23)
	ny, _ := time.LoadLocation("America/New_York")
	tokyo, _ := time.LoadLocation("Asia/Tokyo")
	for _, at := range []time.Time{
		time.Date(2026, 7, 22, 23, 0, 0, 0, ny),   // 03:00Z Jul 23
		time.Date(2026, 7, 23, 8, 0, 0, 0, tokyo), // 23:00Z Jul 22
		time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC),
	} {
		on := DateOf(at)
		state := DeriveEOLState(EOLDeprecated, &shutdown, on)
		days := on.DaysUntil(shutdown)
		if (state == EOLRetired) != (days <= 0) {
			t.Errorf("at %s: state=%q but daysRemaining=%d (self-contradictory)", at, state, days)
		}
	}
}

// TestEOLStateRankUnknownIsLowest is the honesty invariant in rank form: an
// absent record must never outrank a real one, so a gate asking for evidence of
// a problem can never be satisfied by "we don't know".
func TestEOLStateRankUnknownIsLowest(t *testing.T) {
	if EOLStateRank(EOLUnknown) != 0 {
		t.Errorf("unknown rank = %d, want 0", EOLStateRank(EOLUnknown))
	}
	if EOLStateRank(EOLRetired) <= EOLStateRank(EOLDeprecated) ||
		EOLStateRank(EOLDeprecated) <= EOLStateRank(EOLSupported) ||
		EOLStateRank(EOLSupported) <= EOLStateRank(EOLUnknown) {
		t.Error("rank order must be retired > deprecated > supported > unknown")
	}
}

func TestEOLStatesWorstFirst(t *testing.T) {
	got := EOLStates()
	want := []EOLState{EOLRetired, EOLDeprecated, EOLSupported, EOLUnknown}
	if len(got) != len(want) {
		t.Fatalf("EOLStates() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("EOLStates()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
