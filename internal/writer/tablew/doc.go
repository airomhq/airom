// Package tablew renders the human-facing terminal summary (ARCHITECTURE.md
// §11): KIND | NAME | VERSION | PROVIDER | CONF | EVIDENCE (rendered "n occ"),
// TTY-aware (width, color, non-TTY fallback). A wide mode (writer.Options.
// TableWide) expands per-component file:line evidence lists. It is the default
// sink for interactive runs and, like every writer, a pure projection of the
// assembled Inventory (invariant P5) — it renders nothing the graph does not
// already carry.
package tablew
