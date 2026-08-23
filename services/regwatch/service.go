package regwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Service coordinates legislative scraping, semantic diffing, and alert distribution.
type Service struct {
	mu             sync.RWMutex
	scraper        *RegulatoryScraper
	diffEngine     *DiffEngine
	cache          map[Jurisdiction]StatutoryDocument
	alerts         []RegulatoryAlert
	alertListeners []func(RegulatoryAlert)
}

// NewService initializes a RegWatch monitoring service.
func NewService(scraperCfg ScraperConfig) *Service {
	scraper := NewRegulatoryScraper(scraperCfg, nil)
	diffEngine := NewDiffEngine()

	svc := &Service{
		scraper:    scraper,
		diffEngine: diffEngine,
		cache:      make(map[Jurisdiction]StatutoryDocument),
		alerts:     []RegulatoryAlert{},
	}

	// Initialize baseline cache from authoritative statutes
	jurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
		JurisdictionUSFederal,
	}

	for _, j := range jurisdictions {
		if doc, err := scraper.GetBuiltinDocument(j); err == nil {
			svc.cache[j] = *doc
		}
	}

	return svc
}

// CheckJurisdiction scans a single jurisdiction and returns a diff and any new alerts.
func (s *Service) CheckJurisdiction(ctx context.Context, j Jurisdiction) (StatutoryDiff, *RegulatoryAlert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldDoc, hasOld := s.cache[j]
	if !hasOld {
		built, err := s.scraper.GetBuiltinDocument(j)
		if err != nil {
			return StatutoryDiff{}, nil, err
		}
		oldDoc = *built
		s.cache[j] = oldDoc
	}

	newDoc, err := s.scraper.FetchJurisdictionDocument(ctx, j)
	if err != nil {
		return StatutoryDiff{}, nil, fmt.Errorf("failed to fetch document for %s: %w", j, err)
	}

	diff := s.diffEngine.ComputeDiff(oldDoc, *newDoc)

	var alert *RegulatoryAlert
	if diff.HasChanges {
		s.cache[j] = *newDoc

		alertID := fmt.Sprintf("alert-%s-%d", j, time.Now().UTC().UnixNano())
		alert = &RegulatoryAlert{
			ID:                alertID,
			Jurisdiction:      j,
			Title:             fmt.Sprintf("Statutory Update: %s", newDoc.Title),
			Severity:          diff.MaxSeverity,
			EffectiveDate:     newDoc.EffectiveDate,
			Summary:           diff.Summary,
			ImpactedRulepacks: diff.ImpactedRulepacks,
			ActionRequired:    deriveActionRequired(diff.MaxSeverity),
			CreatedAt:         time.Now().UTC(),
		}

		s.alerts = append(s.alerts, *alert)
		for _, listener := range s.alertListeners {
			go listener(*alert)
		}
	}

	return diff, alert, nil
}

// CheckAllJurisdictions evaluates all monitored global jurisdictions.
func (s *Service) CheckAllJurisdictions(ctx context.Context) ([]StatutoryDiff, []RegulatoryAlert, error) {
	jurisdictions := []Jurisdiction{
		JurisdictionColorado,
		JurisdictionCalifornia,
		JurisdictionNYC,
		JurisdictionEU,
		JurisdictionIllinois,
		JurisdictionTexas,
		JurisdictionVirginia,
		JurisdictionUSFederal,
	}

	var diffs []StatutoryDiff
	var newAlerts []RegulatoryAlert

	for _, j := range jurisdictions {
		diff, alert, err := s.CheckJurisdiction(ctx, j)
		if err != nil {
			continue
		}
		diffs = append(diffs, diff)
		if alert != nil {
			newAlerts = append(newAlerts, *alert)
		}
	}

	return diffs, newAlerts, nil
}

// GetCachedDocument retrieves the current baseline statutory document for a jurisdiction.
func (s *Service) GetCachedDocument(j Jurisdiction) (StatutoryDocument, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	doc, ok := s.cache[j]
	return doc, ok
}

// GetAlerts returns all recorded regulatory alerts.
func (s *Service) GetAlerts() []RegulatoryAlert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]RegulatoryAlert, len(s.alerts))
	copy(result, s.alerts)
	return result
}

// SubscribeAlerts attaches a callback listener for newly detected statutory deltas.
func (s *Service) SubscribeAlerts(cb func(RegulatoryAlert)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.alertListeners = append(s.alertListeners, cb)
}

func deriveActionRequired(sev DeltaSeverity) string {
	switch sev {
	case SeverityBreaking:
		return "Execute 'airom scan' to verify new statutory controls and update attestation package."
	case SeverityClarification:
		return "Review updated technical definitions against deployed component metadata."
	default:
		return "Informational statutory notice. No immediate remediation required."
	}
}

// Routes returns the HTTP handler for mounting the regwatch service.
func (s *Service) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/regwatch/alerts", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(s.GetAlerts())
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy", "service": "regwatch"})
	})
	return mux
}
