package filing

import (
	"fmt"
	"strings"
	"time"
)

// RenewalEngine calculates statutory renewal schedules, modification triggers, and deadline urgencies.
type RenewalEngine struct{}

// NewRenewalEngine creates a new RenewalEngine.
func NewRenewalEngine() *RenewalEngine {
	return &RenewalEngine{}
}

// FilingHistoryMap maps each jurisdiction to its most recent statutory filing date.
type FilingHistoryMap map[Jurisdiction]time.Time

// SubstantialModMap maps each jurisdiction to the date of substantial algorithmic modification (if any).
type SubstantialModMap map[Jurisdiction]time.Time

// ComputeCalendar calculates the full compliance deadline schedule across all jurisdictions.
func (e *RenewalEngine) ComputeCalendar(orgID string, history FilingHistoryMap, mods SubstantialModMap, now time.Time) *RenewalCalendar {
	if now.IsZero() {
		now = time.Now().UTC()
	}

	jurisdictions := []struct {
		j       Jurisdiction
		mandate string
		cycle   int
		action  string
	}{
		{
			j:       JurisdictionColorado,
			mandate: "CO SB 24-205 § 6-1-1703: Annual Risk Management & 90-Day Substantial Mod Review",
			cycle:   365,
			action:  "Generate and submit Colorado Risk Management & Algorithmic Impact Attestation",
		},
		{
			j:       JurisdictionNYC,
			mandate: "NYC DCWP LL144 § 20-870: Annual AEDT Independent Bias Audit & 10-Day Notice",
			cycle:   365,
			action:  "Publish independent bias audit summary and verify 10-day candidate notification window",
		},
		{
			j:       JurisdictionCalifornia,
			mandate: "CA AB 2013 § 22757: Generative AI Training Data & Provenance Disclosure",
			cycle:   365,
			action:  "Update public AI training data disclosure and verify consumer opt-out endpoints",
		},
		{
			j:       JurisdictionEU,
			mandate: "Regulation (EU) 2024/1689: Article 50 Transparency & Post-Market Monitoring",
			cycle:   365,
			action:  "Perform post-market monitoring review and update conformity assessment declaration",
		},
		{
			j:       JurisdictionIllinois,
			mandate: "740 ILCS 14/15: Annual Biometric Data Retention Schedule & Purge Review",
			cycle:   365,
			action:  "Audit biometric retention records and execute cryptographic purge for expired data",
		},
		{
			j:       JurisdictionTexas,
			mandate: "Tex. Gov't Code § 2054.601: Annual Automated Decision System Inventory",
			cycle:   365,
			action:  "Submit updated state agency algorithmic inventory and risk classification report",
		},
		{
			j:       JurisdictionVirginia,
			mandate: "Va. Code § 59.1-575: Annual Data Protection Assessment (DPA) Renewal",
			cycle:   365,
			action:  "Refresh Data Protection Assessment for profiling and high-impact automated decisions",
		},
	}

	calendar := &RenewalCalendar{
		OrganizationID: orgID,
		GeneratedAt:    now,
		Items:          make([]RenewalScheduleItem, 0, len(jurisdictions)),
	}

	for _, rule := range jurisdictions {
		var lastFiling *time.Time
		if t, ok := history[rule.j]; ok && !t.IsZero() {
			lastFiling = &t
		}

		var subMod *time.Time
		if t, ok := mods[rule.j]; ok && !t.IsZero() {
			subMod = &t
		}

		// Calculate statutory deadline date
		// Standard cycle deadline: LastFiling + cycleDuration (or Now + 30d if never filed)
		var deadline time.Time
		if lastFiling != nil {
			deadline = lastFiling.AddDate(0, 0, rule.cycle)
		} else {
			// Initial statutory filing grace period (30 days from today)
			deadline = now.AddDate(0, 0, 30)
		}

		// Statutory Substantial Modification Trigger (e.g. CO SB 24-205 & EU AI Act require review within 90 days of modification)
		if subMod != nil {
			modDeadline := subMod.AddDate(0, 0, 90)
			if modDeadline.Before(deadline) {
				deadline = modDeadline
			}
		}

		// Calculate days remaining
		diffHours := deadline.Sub(now).Hours()
		daysRemaining := int(diffHours / 24)
		if diffHours < 0 && daysRemaining == 0 {
			daysRemaining = -1
		}

		urgency := ClassifyUrgency(daysRemaining)

		switch urgency {
		case UrgencyOverdue:
			calendar.OverdueCount++
		case UrgencyUrgent1D, UrgencyUpcoming7D:
			calendar.UrgentCount++
		case UrgencyUpcoming14D, UrgencyUpcoming30D, UrgencyUpcoming90D:
			calendar.UpcomingCount++
		case UrgencyCurrent:
			calendar.CurrentCount++
		}

		item := RenewalScheduleItem{
			Jurisdiction:       rule.j,
			StatutoryMandate:   rule.mandate,
			CycleDurationDays:  rule.cycle,
			LastFilingDate:     lastFiling,
			NextDeadlineDate:   deadline,
			DaysRemaining:      daysRemaining,
			Urgency:            urgency,
			RequiredAction:     rule.action,
			AutoFilingEligible: true,
			SubstantialModDate: subMod,
		}

		calendar.Items = append(calendar.Items, item)
	}

	return calendar
}

// ClassifyUrgency determines the urgency rating based on days remaining until deadline.
func ClassifyUrgency(daysRemaining int) RenewalUrgency {
	if daysRemaining < 0 {
		return UrgencyOverdue
	}
	if daysRemaining <= 1 {
		return UrgencyUrgent1D
	}
	if daysRemaining <= 7 {
		return UrgencyUpcoming7D
	}
	if daysRemaining <= 14 {
		return UrgencyUpcoming14D
	}
	if daysRemaining <= 30 {
		return UrgencyUpcoming30D
	}
	if daysRemaining <= 90 {
		return UrgencyUpcoming90D
	}
	return UrgencyCurrent
}

// RenderCalendarTable generates an ASCII dashboard table of the renewal calendar.
func (e *RenewalEngine) RenderCalendarTable(cal *RenewalCalendar) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "  AIROM STATUTORY COMPLIANCE RENEWAL CALENDAR & DEADLINE TRACKER\n")
	fmt.Fprintf(&sb, "  Organization: %s | Generated: %s\n", cal.OrganizationID, cal.GeneratedAt.UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&sb, "  Overdue: %d | Urgent (<=7d): %d | Upcoming (<=90d): %d | Current (>90d): %d\n",
		cal.OverdueCount, cal.UrgentCount, cal.UpcomingCount, cal.CurrentCount)
	fmt.Fprintf(&sb, "====================================================================================================\n")
	fmt.Fprintf(&sb, "%-12s | %-12s | %-10s | %-14s | %-42s\n", "JURISDICTION", "DEADLINE", "DAYS LEFT", "URGENCY", "STATUTORY MANDATE")
	fmt.Fprintf(&sb, "-------------+--------------+------------+----------------+-------------------------------------------\n")

	for _, item := range cal.Items {
		deadlineStr := item.NextDeadlineDate.Format("2006-01-02")
		daysStr := fmt.Sprintf("%d days", item.DaysRemaining)
		if item.DaysRemaining < 0 {
			daysStr = fmt.Sprintf("-%d days", -item.DaysRemaining)
		} else if item.DaysRemaining == 0 {
			daysStr = "TODAY"
		}

		mandateShort := item.StatutoryMandate
		if len(mandateShort) > 42 {
			mandateShort = mandateShort[:39] + "..."
		}

		fmt.Fprintf(&sb, "%-12s | %-12s | %-10s | %-14s | %-42s\n",
			item.Jurisdiction, deadlineStr, daysStr, item.Urgency, mandateShort)
	}
	fmt.Fprintf(&sb, "====================================================================================================\n")

	return sb.String()
}
