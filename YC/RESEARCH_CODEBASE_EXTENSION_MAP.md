# AIROM Codebase — Engineering Extension Map & Integration Points

This document maps every integration point needed to build compliance features into the existing AIROM scanner.

## 1. CLI Command Registration Pattern
- Files: `cmd/airom/main.go`, `internal/cli/cli.go`, `internal/cli/commands.go`
- Pattern: Each command is a function returning `*cobra.Command`. Commands are decoupled from scan logic — they parse flags, build `*app.Config`, and delegate to `app.Run`.
- Example (from codebase):
```go
func newFSCmd() *cobra.Command {
    return &cobra.Command{
        Use:     "fs <path>",
        GroupID: groupScan,
        Short:   "Scan a directory tree",
        Args:    exactArgs(1, "exactly one <path>"),
        RunE: func(cmd *cobra.Command, args []string) error {
            return runWith(cmd, app.SourceFS, args[0])
        },
    }
}
```
- New Commands Needed:
  - `newApproveCmd()` in `internal/cli/commands.go` -> `airom approve <purl> --scope <glob>`
  - `newRevokeCmd()` in `internal/cli/commands.go` -> `airom revoke <purl> --reason <msg>`
  - `newCheckCmd()` in `internal/cli/commands.go` -> `airom check --approved`
  - Register all three in `newRootCmd()` inside `internal/cli/cli.go`

## 2. Assembler Extension Point for Governance
- File: `internal/assemble/assemble.go`
- The Assembler merges `detect.Finding` claims into canonical `airom.Component` graphs.
- Key method: `draft.finish()` — this is where components get finalized.
- EXACT injection point for `.airomapproved` checking:
```go
func (d *draft) finish() airom.Component {
    c := airom.Component{
        ID:   d.id,
        Kind: d.kind,
        Name: d.name,
        // ...
    }
    // ---> INJECT GOVERNANCE LOGIC HERE <---
    // c.Properties = append(c.Properties, airom.Property{
    //     Name: "airom:governance.status", 
    //     Value: checkApproved(d.name),
    // })
    return c
}
```
- This injection is the ONLY place governance status should be set. It maintains the invariant that detectors emit claims only and the assembler owns identity.

## 3. Rule Engine Internals
- File: `internal/ruleengine/ruleengine.go`
- Rule struct:
```go
type Rule struct {
    ID            string         `yaml:"id"`
    Kind          string         `yaml:"kind"`
    Keywords      []string       `yaml:"keywords"`
    Pattern       string         `yaml:"pattern"`
    Claim         ClaimTmpl      `yaml:"claim"`
    Relations     []RelationTmpl `yaml:"relations,omitempty"`
    CaptureParams *CaptureParams `yaml:"capture_params"`
}
```
- Engine logic: Loads YAML packs into Ruleset via `ParsePack`/`applyLayer`. Aho-Corasick keyword filtering -> regex matching within code/string regions -> ClaimTmpl with variable substitution.
- Can regulation packs reuse this? YES for text-pattern matching. NO for deep semantic analysis (need native Go detectors via SDK).

## 4. Compliance Mapping Engine (ZERO-CODE EXTENSION)
- Files: `internal/compliance/compliance.go`, `pkg/airom/compliance.go`
- Output: `airom.ComplianceResult` containing `ControlOutcome` with `ControlState` (met/gap/manual), `Rationale`, `Evidence` (component IDs), `Counter` gaps.
- Spec compilation: `loadFrameworks()` reads `//go:embed specs/*.yaml`. Each control has `evidence_of` or `gap_if` DSL expressions.
- **CRITICAL: Adding a new compliance framework (e.g., Colorado AI Act) requires ZERO Go code changes. Just add a YAML file to `specs/` directory.**
- This is the primary extension mechanism for regulation packs.

## 5. Writer Pipeline
- File: `internal/writer/writer.go`
- Interface:
```go
type Writer interface {
    Format() string
    Write(w io.Writer, inv *airom.Inventory) error
}
```
- Registration: `registry = map[string]factory{}`. New writers register via `init()`. CLI's `-o format=file` flag automatically supports registered writers.
- New writers needed: `internal/writer/reportw` (compliance report), `internal/writer/filingw` (filing form/documentation)

## 6. Rule Pack YAML Schema
- Example from `rules/models/openai.yaml` and `rules/frameworks/langchain.yaml`:
```yaml
pack: langchain
version: 1
rules:
  - id: langchain/client-construct
    kind: framework
    provider: langchain
    languages: [python, javascript, typescript]
    keywords: ["ChatOpenAI", "LLMChain"]
    pattern: '\b(?:ChatOpenAI|LLMChain)\s*\('
    regions: [code]
    claim: { name: "langchain" }
    confidence: 0.7
```
- Adding new packs: Create `.yaml` under `rules/<domain>/`, add test fixtures in `rules/testdata/`, validate with `airom rules test <file>`.

## 7. Signed Update Channel
- Files: `internal/cli/rules.go` (`newRulesUpdateCmd`), `internal/app/update.go`
- Mechanics: `airom rules update` hits CDN, verifies ed25519 cosign signatures. Flag `--insecure-skip-signature` available.
- Regulation packs CAN use this channel if packaged in the official airom-rules bundle zip.

## 8. Public SDK (Extension Contract)
- Files: `pkg/airom/detect/detect.go`, `pkg/airom/detect/finding.go`
- Selector:
```go
type Selector struct {
    Basenames  []string
    Extensions []string
    PathGlobs  []string
    Languages  []Language
    Need       Need // NeedStat, NeedHeader, NeedContent
}
```
- Interfaces:
  - `FileDetector` (Phase 1 streaming): `DetectFile(ctx, *File) ([]Finding, error)`
  - `ProjectDetector` (Phase 2 cross-file): `DetectProject(ctx, Resolver, *FindingsView) ([]Finding, error)`
- Extension pattern: Map results to `ComponentClaim`, `RiskClaim`, etc., emit `Finding`. Assembler handles dedup/identity.

## 9. Build System & CI
- Static linking: `CGO_ENABLED=0` everywhere
- Release: goreleaser + keyless cosign (OIDC) via GitHub Actions
- Testing: `go test ./...`, 10-second budget fuzzing (`make fuzz`)
- CI invariant check: `go list -deps ./cmd/scan/... | grep net/http` must return exit code 0
- `pkg/airom` must remain stdlib-only

## 10. Implementation Sequence (What Changes Where)

| Feature | Files to Create | Files to Modify | Go Code Changes? |
|---|---|---|---|
| `.airomapproved` parser | `internal/approved/manifest.go`, `internal/approved/manifest_test.go` | None | YES (new package) |
| `airom approve/revoke` CLI | `internal/cli/approve.go`, `internal/cli/revoke.go` | `internal/cli/cli.go` (register commands) | YES |
| Shadow AI detection | None | `internal/assemble/assemble.go` (inject in `draft.finish()`) | YES (small) |
| Colorado AI Act compliance | `internal/compliance/specs/colorado-ai-act.yaml` | None | NO (zero code) |
| NYC LL144 compliance | `internal/compliance/specs/nyc-ll144.yaml` | None | NO (zero code) |
| CA AB 2013 compliance | `internal/compliance/specs/ca-ab2013.yaml` | None | NO (zero code) |
| Compliance report writer | `internal/writer/reportw/reportw.go` | None | YES (new writer) |
