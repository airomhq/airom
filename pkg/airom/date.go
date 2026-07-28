package airom

import (
	"encoding/json"
	"fmt"
	"time"
)

// Date is a calendar day with no time and no zone — the unit a retirement
// announcement is actually made in ("this model stops working on 2026-08-05").
//
// It exists because time.Time is the wrong type for this fact twice over: it
// marshals as 2026-08-05T00:00:00Z, which any consumer west of UTC renders as
// August 4th, and it invites instant comparisons whose answer depends on the
// caller's zone. A day has neither problem.
type Date struct {
	Year  int
	Month time.Month
	Day   int
}

// DateOf truncates an instant to its calendar day in UTC. Every conversion into
// Date funnels through here, so "what day is it" is answered one way process-wide.
func DateOf(t time.Time) Date {
	u := t.UTC()
	return Date{Year: u.Year(), Month: u.Month(), Day: u.Day()}
}

// ParseDate reads a strict YYYY-MM-DD day.
func ParseDate(s string) (Date, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return Date{}, fmt.Errorf("bad date %q (want YYYY-MM-DD)", s)
	}
	return DateOf(t), nil
}

// IsZero reports whether the date is unset.
func (d Date) IsZero() bool { return d == Date{} }

// String renders YYYY-MM-DD.
func (d Date) String() string { return fmt.Sprintf("%04d-%02d-%02d", d.Year, int(d.Month), d.Day) }

// time converts to the midnight-UTC instant, for ordering only.
func (d Date) time() time.Time {
	return time.Date(d.Year, d.Month, d.Day, 0, 0, 0, 0, time.UTC)
}

// Before reports whether d falls before o.
func (d Date) Before(o Date) bool { return d.time().Before(o.time()) }

// After reports whether d falls after o.
func (d Date) After(o Date) bool { return d.time().After(o.time()) }

// Equal reports whether d and o are the same day.
func (d Date) Equal(o Date) bool { return d == o }

// DaysUntil returns whole days from d to o: positive when o is in the future of
// d, negative once past. Both sides are already zone-free, so the answer never
// wobbles with the time of day a scan runs.
func (d Date) DaysUntil(o Date) int {
	return int(o.time().Sub(d.time()).Hours() / 24)
}

// AddDays returns the day n days after d (n may be negative).
func (d Date) AddDays(n int) Date { return DateOf(d.time().AddDate(0, 0, n)) }

// MarshalJSON emits "YYYY-MM-DD" — the precision the fact actually has.
func (d Date) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// UnmarshalJSON accepts "YYYY-MM-DD".
func (d *Date) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseDate(s)
	if err != nil {
		return err
	}
	*d = p
	return nil
}

// MarshalYAML mirrors MarshalJSON so a catalog file and the emitted BOM speak
// the same date language.
func (d Date) MarshalYAML() (any, error) { return d.String(), nil }

// UnmarshalYAML accepts "YYYY-MM-DD".
func (d *Date) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	p, err := ParseDate(s)
	if err != nil {
		return err
	}
	*d = p
	return nil
}
