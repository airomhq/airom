package airom

// Lifecycle is a dated, sourced statement about how long a component will keep
// working. It exists for hosted models, whose retirement is unlike any other
// finding AIROM makes: a CVE is a risk you weigh, but a retired model is a
// calendar fact with a hard consequence — on the shutdown date the provider's
// API stops answering and the application breaks, patched or not.
//
// Every Lifecycle originates in a curated catalog entry transcribed from the
// provider's own deprecation page, carrying that page's URL and the date a
// maintainer last verified it. Nothing here is inferred from naming patterns:
// a model absent from the catalog gets no Lifecycle at all (EOLUnknown), which
// is NOT a claim that it is supported.
//
// The dates are calendar days (Date, not time.Time): a retirement is announced
// as a day, and rendering it as a timestamp would both invent precision and
// shift the date for any reader west of UTC.
type Lifecycle struct {
	State EOLState `json:"state"`
	// Announced is when the provider announced the deprecation.
	Announced *Date `json:"announced,omitempty"`
	// Shutdown is when the model stops being served — the consequence date.
	Shutdown *Date `json:"shutdown,omitempty"`
	// DaysRemaining is Shutdown minus the scan day, derived (never stored):
	// negative once the shutdown date has passed.
	DaysRemaining *int `json:"daysRemaining,omitempty"`
	// Replacement is the provider's named migration target, when they name one.
	Replacement string `json:"replacement,omitempty"`
	// Source identifies the catalog ("airom-catalog"), SourceURL the provider
	// page the record was transcribed from, and Verified when a maintainer last
	// checked it — so a reader can audit and date every claim.
	Source    string `json:"source"`
	SourceURL string `json:"sourceUrl,omitempty"`
	Verified  *Date  `json:"verified,omitempty"`
}

// EOLState is the lifecycle bucket. "unknown" means the catalog has no record —
// deliberately distinct from "supported", which is a positive claim.
type EOLState string

// The lifecycle states, ordered from healthy to broken by EOLStateRank.
const (
	// EOLSupported: the provider lists the model as current.
	EOLSupported EOLState = "supported"
	// EOLDeprecated: retirement announced, the model is still served.
	EOLDeprecated EOLState = "deprecated"
	// EOLRetired: the shutdown date has passed — calls fail today.
	EOLRetired EOLState = "retired"
	// EOLUnknown: no catalog record. Never render this as healthy.
	EOLUnknown EOLState = "unknown"
)

// EOLStates lists the states worst-first, for gate validation and reporting.
func EOLStates() []EOLState {
	return []EOLState{EOLRetired, EOLDeprecated, EOLSupported, EOLUnknown}
}

// EOLStateRank orders states for threshold gating: higher is worse. Unknown
// ranks 0 — it asserts nothing, so it must never satisfy a gate that asks for
// evidence of a problem.
func EOLStateRank(s EOLState) int {
	switch s {
	case EOLRetired:
		return 3
	case EOLDeprecated:
		return 2
	case EOLSupported:
		return 1
	default:
		return 0
	}
}

// DeriveEOLState resolves the catalog's announced state against the scan day.
// The catalog records what the provider announced; whether that shutdown has
// *arrived* is a function of when the scan runs, so it is computed here rather
// than stored. This keeps a curated record truthful as time passes without
// anyone re-editing it: a "deprecated" entry becomes "retired" on its own date.
//
// announced is the state from the catalog; shutdown may be nil (a deprecation
// with no date yet), in which case the announced state stands.
//
// State and DaysRemaining are both computed from calendar days, so they can
// never contradict each other — "retired" always pairs with DaysRemaining <= 0.
func DeriveEOLState(announced EOLState, shutdown *Date, on Date) EOLState {
	// An unparseable announced state asserts nothing, and a date attached to
	// nothing does not turn it into a claim: unknown in, unknown out.
	switch announced {
	case EOLSupported, EOLDeprecated, EOLRetired:
	default:
		return EOLUnknown
	}
	if shutdown != nil {
		if on.DaysUntil(*shutdown) <= 0 { // on or after the shutdown day
			return EOLRetired
		}
		// A future shutdown date outranks a stale "supported" in the record:
		// the date is the stronger signal. (The catalog loader rejects that
		// combination, so this only fires for a caller building a Lifecycle
		// directly through the SDK.)
		return EOLDeprecated
	}
	return announced
}
