// Package tablew renders the human-facing terminal summary (ARCHITECTURE.md
// §11): a boxed scan-summary panel followed by a box-drawn component table with
// columns KIND | NAME | VERSION | PROVIDER | CONF | LOCATION (the primary
// path:line sighting) | EVIDENCE (rendered "n occ"), plus RISK | FLAGS when a
// scan surfaces an artifact risk. A wide mode (writer.Options.TableWide)
// expands the full per-component file:line evidence list under each row. It is
// the default sink for interactive runs and, like every writer, a pure
// projection of the assembled Inventory (invariant P5) — it renders nothing the
// graph does not already carry.
package tablew
