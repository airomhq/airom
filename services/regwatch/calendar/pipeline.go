package calendar

import (
	"sort"
	"sync"
	"time"
)

// Pipeline manages statutory deadlines across global jurisdictions.
type Pipeline struct {
	mu         sync.RWMutex
	milestones []StatutoryMilestone
}

// NewPipeline constructs a pipeline populated with authoritative statutory enforcement dates.
func NewPipeline() *Pipeline {
	p := &Pipeline{}

	// 1. Colorado AI Act
	p.RegisterMilestone(StatutoryMilestone{
		MilestoneID:   "CO-SB24-205-ENFORCE",
		Jurisdiction:  "Colorado",
		StatuteName:   "Colorado AI Act (CO SB 24-205)",
		Type:          TypeStatutoryEnactment,
		DeadlineDate:  time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC),
		MandatoryTask: "Deploy risk management policy and technical impact assessment repository.",
		Penalties:     "Civil penalties up to $20,000 per violation.",
	})

	// 2. EU AI Act High-Risk General Purpose AI & Annex IV
	p.RegisterMilestone(StatutoryMilestone{
		MilestoneID:   "EU-AI-ACT-GPAI-ENFORCE",
		Jurisdiction:  "European Union",
		StatuteName:   "EU AI Act (Regulation 2024/1689 Title III)",
		Type:          TypeStatutoryEnactment,
		DeadlineDate:  time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC),
		MandatoryTask: "Complete Annex IV technical documentation and CE conformity marking.",
		Penalties:     "Fines up to €35M or 7% of global annual turnover.",
	})

	// 3. California AB 2013 Generative AI Training Data Transparency
	p.RegisterMilestone(StatutoryMilestone{
		MilestoneID:   "CA-AB2013-ENFORCE",
		Jurisdiction:  "California",
		StatuteName:   "California AI Transparency Act (CA AB 2013)",
		Type:          TypeStatutoryEnactment,
		DeadlineDate:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		MandatoryTask: "Publish public documentation of training datasets and copyright status.",
		Penalties:     "Statutory civil penalties under AG enforcement.",
	})

	return p
}

// RegisterMilestone adds a new statutory milestone.
func (p *Pipeline) RegisterMilestone(m StatutoryMilestone) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.milestones = append(p.milestones, m)
}

// ComputeActionNotices calculates days remaining until deadline relative to reference time.
func (p *Pipeline) ComputeActionNotices(now time.Time) []ActionNotice {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var notices []ActionNotice

	for _, m := range p.milestones {
		diff := m.DeadlineDate.Sub(now)
		days := int(diff.Hours() / 24)

		isOverdue := days < 0
		urgency := "MONITORING"
		if isOverdue {
			urgency = "STATUTORY_VIOLATION_OVERDUE"
		} else if days <= 30 {
			urgency = "URGENT_ACTION_REQUIRED"
		} else if days <= 90 {
			urgency = "UPCOMING_DEADLINE"
		}

		notices = append(notices, ActionNotice{
			MilestoneID:   m.MilestoneID,
			Jurisdiction:  m.Jurisdiction,
			StatuteName:   m.StatuteName,
			DaysRemaining: days,
			IsOverdue:     isOverdue,
			Urgency:       urgency,
			Task:          m.MandatoryTask,
		})
	}

	// Sort notices by days remaining (closest first)
	sort.Slice(notices, func(i, j int) bool {
		return notices[i].DaysRemaining < notices[j].DaysRemaining
	})

	return notices
}
