// Package eol is the hosted-model end-of-life overlay: it matches the AI models
// AIROM inventoried against a curated catalog of provider retirement
// announcements and attaches a dated, sourced Lifecycle to them.
//
// A model EOL is unlike the other findings AIROM makes. A CVE is a risk you
// weigh; a retired model is a calendar fact with a hard consequence — on the
// shutdown date the provider's API stops answering and the application breaks,
// patched or not. So the overlay answers one question: what in this stack stops
// working, when, and what do I move to?
//
// Two properties keep it honest:
//
//   - Every record is TRANSCRIBED from the provider's own deprecation page,
//     carrying that page's URL and the date a maintainer verified it. Nothing is
//     inferred from naming patterns ("-preview", a date suffix) — an
//     announcement or nothing.
//   - A model absent from the catalog gets NO Lifecycle. That is "unknown", not
//     "supported": the overlay never implies a model is healthy just because
//     nobody has curated it.
//
// Unlike the CVE overlay this needs no network — the catalog is embedded (and,
// later, refreshed through the signed airom-rules bundle) — so it works under
// --offline.
package eol

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/airomhq/airom/pkg/airom"
)

//go:embed catalog/*.yaml
var catalogFS embed.FS

// StaleAfterDays is how long a catalog record may go unverified before the scan
// says so. Provider deprecation pages change without notice, so a catalog that
// nobody has checked in a quarter is a fact worth surfacing rather than
// silently trusting.
const StaleAfterDays = 90

// providerFile is one provider's catalog as written on disk.
type providerFile struct {
	Provider string       `yaml:"provider"`
	Version  int          `yaml:"version"`
	Source   string       `yaml:"source"`   // the provider page these records come from
	Verified string       `yaml:"verified"` // when a maintainer last checked that page
	Models   []modelEntry `yaml:"models"`
}

// modelEntry is one model's announced lifecycle.
type modelEntry struct {
	ID          string   `yaml:"id"`
	Aliases     []string `yaml:"aliases"`
	State       string   `yaml:"state"`
	Announced   string   `yaml:"announced"`
	Shutdown    string   `yaml:"shutdown"`
	Replacement string   `yaml:"replacement"`
	// Per-record overrides; default to the file's values.
	Source   string `yaml:"source"`
	Verified string `yaml:"verified"`
}

// record is a validated, parsed catalog entry.
type record struct {
	provider    string
	id          string
	state       airom.EOLState
	announced   *airom.Date
	shutdown    *airom.Date
	replacement string
	source      string
	verified    airom.Date
}

// Catalog is the compiled lookup: (provider, model-id-or-alias) → record.
type Catalog struct {
	byKey map[string]record
	// verifiedByProvider dates each provider file's last verification. Staleness
	// reports the OLDEST of these, not the newest: a freshly-checked openai.yaml
	// must not vouch for an anthropic.yaml nobody has touched in a year.
	verifiedByProvider map[string]airom.Date
	// loadedOn is the day the catalog was loaded, used to reject verification
	// dates that claim to be from the future.
	loadedOn airom.Date
}

// key builds the case-folded lookup key. Providers publish model ids in
// lowercase but code may not, so matching folds case — it never fuzzy-matches:
// a wrong EOL claim is worse than no claim.
func key(provider, id string) string {
	return strings.ToLower(strings.TrimSpace(provider)) + "\x00" + strings.ToLower(strings.TrimSpace(id))
}

// Load parses and validates the embedded catalog. A malformed catalog ships in
// the binary, so any error here means the build itself is broken.
func Load() (*Catalog, error) { return LoadOn(airom.DateOf(time.Now())) }

// LoadOn is Load with an explicit "today" for INTEGRITY validation — is this
// data internally sane, e.g. is a verification date impossibly in the future?
//
// That is a different question from the one Lookup answers ("has this shutdown
// arrived yet?"), and the two must not share a clock. A caller that pins the
// scan date to reproduce a golden is choosing an evaluation day, not claiming
// the world's calendar moved; validating catalog integrity against that pinned
// day would reject a perfectly good catalog verified after it. So the pipeline
// passes real time here and the pinned day to Lookup/Enrich.
func LoadOn(today airom.Date) (*Catalog, error) { return loadFS(catalogFS, "catalog", today) }

// loadFS is Load's testable core: it reads every <dir>/*.yaml from fsys.
func loadFS(fsys fs.FS, dir string, on airom.Date) (*Catalog, error) {
	paths, err := fs.Glob(fsys, dir+"/*.yaml")
	if err != nil {
		return nil, err
	}
	sort.Strings(paths) // deterministic duplicate-detection order
	c := &Catalog{byKey: make(map[string]record), verifiedByProvider: map[string]airom.Date{}, loadedOn: on}
	for _, p := range paths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			return nil, err
		}
		var pf providerFile
		if err := yaml.Unmarshal(data, &pf); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		if err := c.addProvider(p, &pf); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// addProvider validates one provider file and folds its records into the
// catalog. The validation IS the honesty contract: no source, no verified date,
// no unparseable state or date gets in.
func (c *Catalog) addProvider(path string, pf *providerFile) error {
	if strings.TrimSpace(pf.Provider) == "" {
		return fmt.Errorf("%s: provider is required", path)
	}
	if strings.TrimSpace(pf.Source) == "" {
		return fmt.Errorf("%s: source URL is required — every record must cite the provider page it came from", path)
	}
	fileVerified, err := parseDate(pf.Verified)
	if err != nil || fileVerified == nil {
		return fmt.Errorf("%s: verified date is required (YYYY-MM-DD) — an unverifiable record is not a fact", path)
	}
	// A future verification date cannot be true, and a typo'd year would park
	// the staleness clock permanently in the future — disabling the one guard
	// against this data rotting.
	if fileVerified.After(c.loadedOn) {
		return fmt.Errorf("%s: verified date %s is in the future (today is %s)", path, fileVerified, c.loadedOn)
	}
	if len(pf.Models) == 0 {
		return fmt.Errorf("%s: no models", path)
	}

	for _, m := range pf.Models {
		if strings.TrimSpace(m.ID) == "" {
			return fmt.Errorf("%s: a model entry has no id", path)
		}
		state, err := parseState(m.State)
		if err != nil {
			return fmt.Errorf("%s: model %q: %w", path, m.ID, err)
		}
		announced, err := parseDate(m.Announced)
		if err != nil {
			return fmt.Errorf("%s: model %q: announced: %w", path, m.ID, err)
		}
		shutdown, err := parseDate(m.Shutdown)
		if err != nil {
			return fmt.Errorf("%s: model %q: shutdown: %w", path, m.ID, err)
		}
		// A deprecation with no date is legal (announced, date TBA), but a
		// shutdown date with no announcement is not — it would be undated
		// hearsay about when something breaks.
		if shutdown != nil && announced == nil {
			return fmt.Errorf("%s: model %q: shutdown without announced date", path, m.ID)
		}
		// Transposing a date pair during transcription is the likeliest hand-entry
		// error, and it silently produces a wrong DaysRemaining. Nothing can be
		// retired before it was announced.
		if shutdown != nil && shutdown.Before(*announced) {
			return fmt.Errorf("%s: model %q: shutdown %s precedes announced %s", path, m.ID, shutdown, announced)
		}
		if state == airom.EOLSupported && shutdown != nil {
			return fmt.Errorf("%s: model %q: state 'supported' cannot carry a shutdown date", path, m.ID)
		}
		verified := *fileVerified
		if m.Verified != "" {
			v, err := parseDate(m.Verified)
			if err != nil || v == nil {
				return fmt.Errorf("%s: model %q: verified: bad date", path, m.ID)
			}
			verified = *v
		}
		source := pf.Source
		if m.Source != "" {
			source = m.Source
		}

		rec := record{
			provider: pf.Provider, id: m.ID, state: state,
			announced: announced, shutdown: shutdown,
			replacement: m.Replacement, source: source, verified: verified,
		}
		for _, name := range append([]string{m.ID}, m.Aliases...) {
			if strings.TrimSpace(name) == "" {
				return fmt.Errorf("%s: model %q: empty alias", path, m.ID)
			}
			k := key(pf.Provider, name)
			if prev, dup := c.byKey[k]; dup {
				return fmt.Errorf("%s: %q is claimed by both %q and %q", path, name, prev.id, m.ID)
			}
			c.byKey[k] = rec
		}
		if prev, ok := c.verifiedByProvider[pf.Provider]; !ok || verified.Before(prev) {
			c.verifiedByProvider[pf.Provider] = verified // oldest wins: staleness is per-provider
		}
	}
	return nil
}

// Lookup resolves (provider, modelID) to a Lifecycle as of the scan day `on`.
// It returns nil when the catalog has no record — the caller must treat that as
// "unknown", never as "supported".
//
// Every date is copied out, never aliased: the returned Lifecycle is handed to
// writers and SDK callers, and one of them normalizing a date in place would
// otherwise rewrite the shared catalog for the rest of the process.
func (c *Catalog) Lookup(provider, modelID string, on airom.Date) *airom.Lifecycle {
	if c == nil {
		return nil
	}
	rec, ok := c.byKey[key(provider, modelID)]
	if !ok {
		return nil
	}
	lc := &airom.Lifecycle{
		State:       airom.DeriveEOLState(rec.state, rec.shutdown, on),
		Announced:   copyDate(rec.announced),
		Shutdown:    copyDate(rec.shutdown),
		Replacement: rec.replacement,
		Source:      "airom-catalog",
		SourceURL:   rec.source,
	}
	v := rec.verified
	lc.Verified = &v
	if rec.shutdown != nil {
		d := on.DaysUntil(*rec.shutdown)
		lc.DaysRemaining = &d
	}
	return lc
}

// copyDate returns a fresh pointer to the same day (nil stays nil).
func copyDate(d *airom.Date) *airom.Date {
	if d == nil {
		return nil
	}
	v := *d
	return &v
}

// Size reports how many distinct lookup keys (ids plus aliases) the catalog
// holds — used by diagnostics and tests.
func (c *Catalog) Size() int {
	if c == nil {
		return 0
	}
	return len(c.byKey)
}

// StalenessWarning returns a non-empty message when the LEAST recently verified
// provider is older than StaleAfterDays. Model deprecation pages change without
// notice, so rotting data must be visible rather than silently trusted — and it
// reports the oldest provider by name, because a freshly-checked openai.yaml
// must not vouch for an anthropic.yaml nobody has touched in a year.
func (c *Catalog) StalenessWarning(on airom.Date) string {
	if c == nil || len(c.verifiedByProvider) == 0 {
		return ""
	}
	// Deterministic pick: oldest date, then provider name.
	var worstProvider string
	var worst airom.Date
	for _, p := range sortedProviders(c.verifiedByProvider) {
		d := c.verifiedByProvider[p]
		if worstProvider == "" || d.Before(worst) {
			worstProvider, worst = p, d
		}
	}
	age := worst.DaysUntil(on)
	if age < 0 {
		// Verified AFTER the day being evaluated. Legitimate when scanning "as
		// of" a past date, but it is not freshness — the catalog knows things
		// the scan date does not — so say so rather than let a negative number
		// slide through the threshold below as if it were healthy.
		return fmt.Sprintf(
			"eol: the %s model lifecycle catalog was verified %s, after the scan date %s; retirement states are evaluated as of the scan date",
			worstProvider, worst, on,
		)
	}
	if age <= StaleAfterDays {
		return ""
	}
	// Name the action that actually helps. The catalog is embedded in the
	// binary, so `airom rules update` — which fetches the RULE bundle — cannot
	// refresh it; telling a user to run it would send them in a circle, warning
	// unchanged, until they upgraded anyway.
	return fmt.Sprintf(
		"eol: the %s model lifecycle catalog was last verified %d days ago (%s); retirement dates may be out of date — upgrade airom for a newer catalog",
		worstProvider, age, worst,
	)
}

// sortedProviders returns the provider keys in a stable order (P7).
func sortedProviders(m map[string]airom.Date) []string {
	out := make([]string, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// parseState maps the catalog's announced state. "unknown" is deliberately not
// accepted: a record exists precisely because there is something to say.
func parseState(s string) (airom.EOLState, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "supported":
		return airom.EOLSupported, nil
	case "deprecated":
		return airom.EOLDeprecated, nil
	case "retired":
		return airom.EOLRetired, nil
	case "":
		return "", fmt.Errorf("state is required (supported|deprecated|retired)")
	default:
		return "", fmt.Errorf("unknown state %q (want supported|deprecated|retired)", s)
	}
}

// parseDate accepts an empty string (absent) or a strict YYYY-MM-DD day.
func parseDate(s string) (*airom.Date, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	d, err := airom.ParseDate(s)
	if err != nil {
		return nil, err
	}
	return &d, nil
}
