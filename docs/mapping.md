# AIROM Master Field Mapping

> **Status:** Accepted contract (written in Phase 1 scaffolding) · **Enforced by:** the mapping
> round-trip tests of ARCHITECTURE §14 — landing in **Phase 7** (fuzz-populated `Inventory` →
> native JSON → re-read → identical) and **Phase 8** (CycloneDX output parsed back and asserted
> against this table) · **Companion:** [ARCHITECTURE.md](ARCHITECTURE.md) §5 (domain model),
> §9.4 (purl), §11 (writers), D18 (lines/columns).

## 1. Purpose

Writers are **pure projections**: `func(*airom.Inventory) []byte` (invariant P5). No writer
invents, drops, or re-derives data — every emitted field traces to exactly one domain-model
field, and this document is the single normative statement of that trace. If a writer and this
table disagree, one of them has a bug; the Phase 7/8 round-trip tests turn that disagreement
into a CI failure rather than a docs drift.

Change discipline:

- Any change to the §5 domain model, to a writer's emission, or to the `airom:*` property
  registry (§6.5 below) **must update this file in the same PR**.
- The **native JSON** column is the lossless reference format; every other format is allowed
  to be lossy *only* where a cell below explicitly says so.
- The **SPDX 3.0.1** column is the design target for the v2 writer (ARCHITECTURE §16.1). Rows
  marked ▲ use vocabulary values beyond the subset schema-verified during research
  (`trainedOn`, `testedOn`, `hasInput`, `hasOutput`, `contains`, `dependsOn`, `generates`);
  they are re-verified against the published 3.0.1 vocabulary when that writer lands, with
  `relationshipType: "other"` + element `comment` as the defined fallback.

## 2. How to read the tables

| Marker | Meaning |
|---|---|
| *(native)* | Lossless, spec-native home. |
| *(prop)* | Lossless, but carried in an `airom:*` property (registry in §6.5). |
| *(lossy)* | Information degraded or partially dropped in this format; the native JSON retains full fidelity. The cell says what is lost. |
| — | No home in this format; dropped entirely (recoverable from native JSON). |
| ▲ | SPDX vocabulary value pending re-verification (see §1). |

Conventions used throughout:

- **Native JSON paths** are the mechanical lowerCamelCase serialization of the §5 Go model
  (`SchemaVersion` → `schemaVersion`, `DetectorID` → `detectorId`). Paths inside component
  sub-tables are relative to `components[]`.
- **Tri-states** (`OptString`, `OptInt64`, `OptTime`, `TriState`, `Presence`) serialize per
  §6.4: native JSON uses value / `null` / omitted for Known / Unknown / Absent; SPDX uses the
  `NOASSERTION` discipline; CycloneDX and SARIF omit non-Known values (their consumers have no
  no-assertion concept).
- **CycloneDX** paths are against `bom-1.6.schema.json`. The 1.7 writer
  (`--cdx-version 1.7`) is identical for everything AIROM emits — the 1.6→1.7 delta is four
  new `externalReferences[].type` values (`patent`, `patent-family`, `patent-assertion`,
  `citation`), none of which AIROM produces in v1.

---

## 3. Master field mapping

### 3.1 `Inventory` — document envelope

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `SchemaVersion` | — (implied by `bomFormat` + `specVersion`) | — (implied by `CreationInfo.specVersion: "3.0.1"`) | — (implied by `version: "2.1.0"`) | `schemaVersion` *(native)* |
| `Tool` (name, version) | `metadata.tools.components[]` `{type: "application", name, version}` *(native)* | `CreationInfo.createdUsing` → `Tool` element *(native)* | `runs[].tool.driver.{name, semanticVersion, informationUri}` *(native)* | `tool.{name, version}` |
| `Tool.Commit` | `metadata.properties[]` `airom:tool.commit` *(prop)* | `Tool` element `comment` | `runs[].tool.driver.properties["airom:tool.commit"]` *(prop)* | `tool.commit` |
| `Serial` (a full `urn:uuid:<uuid>` URN) | `serialNumber` = `Serial` verbatim *(native; already a `urn:uuid:` URN — a bare UUID is prefixed for hand-built inventories)* | seeds the `SpdxDocument` `spdxId` / document namespace: `https://airom.dev/spdxdocs/<Serial>` (IRI prefix finalized with the v2 writer) | — | `serial` |
| `Timestamp` (RFC 3339 UTC, injectable clock) | `metadata.timestamp` *(native)* | `CreationInfo.created` *(native)* | `runs[].invocations[].endTimeUtc` *(native)* | `timestamp` |
| `Lifecycle` (`"pre-build"` \| `"post-build"`) | `metadata.lifecycles[].phase` *(native — same enum values; never `discovery`, which CDX defines as network discovery)* | *(lossy)* `software_Sbom` element `comment` | — | `lifecycle` |
| `Source.Type` (`dir` \| `repo` \| `image` \| `k8s`) | `metadata.properties[]` `airom:source.type` *(prop)* | — | — | `source.type` |
| `Source` target (path / ref / image digest) | `airom:source.target`, `airom:source.digest` *(prop)* | — | `runs[].originalUriBaseIds.SRCROOT.uri` (`file:///…/` form; path targets only) | `source.target`, `source.digest` |
| `Source` git provenance (remote, commit, dirty) | `airom:source.git.remote`, `airom:source.git.commit`, `airom:source.git.dirty` *(prop)* | — | `runs[].versionControlProvenance[].{repositoryUri, revisionId}`; dirty flag — *(lossy)* | `source.git.{remote, commit, dirty}` |
| `Source` k8s context | `airom:source.k8s.context` *(prop)* | — | — | `source.k8sContext` |
| `Root` | `metadata.component` (`type: "application"`, `bom-ref` = Root ID); root is **not** duplicated in `components[]` | `software_Sbom.rootElement` | — | `root` |
| `Components` | `components[]` *(native)* | `@graph` elements (one per component + shared `CreationInfo`) | `results[]` — **one result per Occurrence**, not per component (§7.3) | `components[]` |
| `Relationships` | see §3.10 — `dependencies[]` / `modelCard…datasets[].ref` / `airom:rel.*` | `Relationship` elements `{from, to[], relationshipType}` | — | `relationships[]` |
| `Unknowns` | *(lossy)* count only: `metadata.properties[]` `airom:unknowns` | — | `runs[].invocations[].toolExecutionNotifications[]` (§3.11) | `unknowns[]` *(native)* |
| `Stats` | — | — | — | `stats` *(native; only when `--stats`)* |

### 3.2 `Component` — identity and shared fields

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `ID` (`"airom:" + hex(sha256(CanonicalKey))[:16]`) | `bom-ref` *(native; never starts with `urn:cdx:` by construction)* | `spdxId` = `https://airom.dev/spdxdocs/<Serial>#<ID-hex>` | input to `partialFingerprints` (§7.2) + `result.properties["airom:componentId"]` *(prop)* | `id` |
| `Kind` | `type` per §4 kind table, **plus** `properties[]` `airom:kind` on every component — the exact kind always survives the coarser CDX enum *(prop)* | element class + `software_primaryPurpose` per §4 | `result.properties["airom:kind"]` *(prop)* | `kind` |
| `Name` | `name` *(native)* | `name` *(native)* | `message.text` (headline) | `name` |
| `Group` | `group` *(native)* | — *(lossy: SPDX 3.0.1 packages have no group/namespace slot; retained in native + CDX)* | `message.text` | `group` |
| `Version` (`OptString`) | `version` (Known only; else omitted) | `software_packageVersion` — **required on `ai_AIPackage`**: tri-state rule §6.4 (`NOASSERTION` when not Known) | `message.text` | `version` (tri-state §6.4) |
| `Provider` (`OptString`) | model kinds: `airom:model.provider`; all other kinds: `airom:provider` *(prop; Known only)* | feeds `suppliedBy` fallback: when `Supplier` is nil, an Agent is minted from Provider; else — | `result.properties["airom:provider"]` *(prop)* | `provider` |
| `PURL` | `purl` *(native; empty string → omitted; policy §6.3)* | `ExternalIdentifier` `{externalIdentifierType: "packageUrl", identifier}` | `result.properties["airom:purl"]` *(prop; only when set)* | `purl` |
| `Licenses` | `licenses[]` — `{license: {id \| name}}` or `{expression}` *(native)* | `hasDeclaredLicense` relationship → license element | — | `licenses[]` |
| `Supplier` (`*Party`) | `supplier.{name, url[]}` *(native)* | `suppliedBy` → Agent — **required on `ai_AIPackage`**: nil + no Provider → `NoAssertionElement` individual | — | `supplier` |
| `Hashes` | `hashes[]` `{alg: "SHA-256", content}` *(native)*. **SHA-256 only**: XXH3 is cache-internal, absent from the CDX `alg` enum, and never emitted by any writer | `verifiedUsing[]` `Hash {algorithm: "sha256", hashValue}` | — (participates in nothing; the fingerprint recipe §7.2 is hash-free) | `hashes[]` `{alg, hex}` |
| `DownloadLocation` (`OptString`) | `externalReferences[]` `{type: "distribution", url}` (Known only) | `software_downloadLocation` — **required on `ai_AIPackage` / `dataset_DatasetPackage`**: tri-state rule §6.4 | — | `downloadLocation` (tri-state) |
| `SourceInfo` (human trail) | `description` *(native)* | element `comment` | — | `sourceInfo` |
| `ReleaseTime` (`OptTime`) | `properties[]` `airom:releaseTime` (RFC 3339) *(prop — CDX 1.6 has no component-level release time)* | `releaseTime` — **required on `ai_AIPackage`**: tri-state rule §6.4 | — | `releaseTime` (tri-state) |
| `Model` / `Data` / `Infra` / `Package` facet | §3.3–§3.6 | §3.3–§3.6 | §3.3–§3.6 | `model` / `data` / `infra` / `package` |
| `Confidence` (assembled, §9.3) | `properties[]` `airom:confidence` *(prop; format §6.2)* | — *(lossy)* | `result.properties["airom:confidence"]` *(prop)* | `confidence` |
| `Evidence` | `evidence.{identity[], occurrences[]}` — §3.8/§3.9. The differentiator: no other AIBOM tool populates these | — *(lossy — the single largest SPDX loss; evidence is native/CDX/SARIF-only)* | the entire `results[]` view is a projection of Evidence | `evidence` |
| `Props` (overflow `[]KV`) | `properties[]` appended verbatim; every name must be `airom:`-namespaced and registered in §6.5 (assembler-validated) | — *(lossy)* | — | `props[]` |
| `Attestations` (`[]AttestationRef`; recorded, not verified — v2 verifies, §16.2) | `externalReferences[]` `{type: "attestation", url}` | — (v2, alongside verification) | — | `attestations[]` |

### 3.3 `ModelFacet` (kinds `hosted-llm`, `local-model-file`, `embedding-model`)

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `Task` (`OptString`) | `modelCard.modelParameters.task` *(native)* | `ai_domain[]` *(lossy — nearest available slot; task ≠ domain)* | — | `model.task` |
| `Architecture` (`OptString`) | `modelCard.modelParameters.modelArchitecture` *(native)* | `ai_typeOfModel[]` | — | `model.architecture` |
| `ParamCount` (`OptInt64`, exact from GGUF/safetensors headers) | `properties[]` `airom:model.paramCount` *(prop — `modelParameters` has no parameter-count field)* | — *(lossy)* | — | `model.paramCount` |
| `Quantization` (`OptString`) | `airom:model.quantization` *(prop)* | — | — | `model.quantization` |
| `ContextLength` (`OptInt64`) | `airom:model.contextLength` *(prop)* | — | — | `model.contextLength` |
| `Format` (`OptString`: `"gguf"`, `"safetensors"`, …) | `airom:model.format` *(prop)* | — | — | `model.format` |
| `BaseModel` (`OptString`) | `airom:model.baseModel` *(prop)*; additionally a `derived-from` relationship when the base component exists in the graph (§3.10) | edge → `descendantOf` ▲ | — | `model.baseModel` |
| `GenerationParams` (`[]BoundParam`) | §3.7 | — *(lossy — SPDX `ai_hyperparameter` is training-time config; inference params have no home)* | — | `model.generationParams[]` |
| `PickleRisk` (`*PickleRisk`) | `properties[]` `airom:pickle.risk` (summary level); suspicious imports `airom:pickle.imports` (`\|`-joined) *(prop)* | — | `result.properties["airom:pickle.risk"]` on that component's results *(prop; level stays `note` — §7.1)* | `model.pickleRisk` *(native, full struct)* |
| `Card` (`*ModelCard`) | §3.4 | §3.4 | — | `model.card` |

**`modelCard` emission rule:** the CDX writer emits a `modelCard` object iff the component's
CDX type is `machine-learning-model` **and** at least one of {`Task` Known, `Architecture`
Known, `Card != nil`, an outgoing `trained-on` edge} holds. The schema constraint is enforced
in reverse too: `modelCard` is never attached to any other component type ("SHOULD be
specified for any component of type machine-learning-model and must not be specified for
other component types").

### 3.4 `ModelCard` (CDX modelCard superset: metrics, considerations, energy)

The Go enumeration of `ModelCard` lands with the `pkg/airom` domain-model implementation; the
spec homes below are fixed now and the round-trip test binds to them in Phase 7/8.

| Card group | CycloneDX 1.6 | SPDX 3.0.1 (v2) | Native JSON |
|---|---|---|---|
| Learning approach | `modelCard.modelParameters.approach.type` (enum `supervised \| unsupervised \| reinforcement-learning \| semi-supervised \| self-supervised`) *(native)* | `ai_typeOfModel[]` *(lossy concat)* | `model.card.approach` |
| Architecture family | `modelCard.modelParameters.architectureFamily` *(native)* | `ai_typeOfModel[]` *(lossy concat)* | `model.card.architectureFamily` |
| Inputs / outputs (formats) | `modelCard.modelParameters.inputs[].format` / `outputs[].format` *(native)* | `hasInput` / `hasOutput` relationships to artifact elements | `model.card.inputs[]`, `model.card.outputs[]` |
| Hyperparameters (training-time) | `modelCard.properties[]` `airom:hyperparam.<key>` *(prop — no native modelCard slot)* | `ai_hyperparameter[]` `{key, value}` *(native)* | `model.card.hyperparameters[]` |
| Metrics | `modelCard.quantitativeAnalysis.performanceMetrics[].{type, value, slice, confidenceInterval.{lowerBound, upperBound}}` *(native — **values are strings**, never numbers, per schema)* | `ai_metric[]` + `ai_metricDecisionThreshold[]` (DictionaryEntry) | `model.card.metrics[]` |
| Considerations: users / use cases | `modelCard.considerations.users[]` / `useCases[]` *(native)* | `ai_informationAboutApplication` *(lossy — joined into one string, 0..1)* | `model.card.users[]`, `model.card.useCases[]` |
| Technical limitations | `modelCard.considerations.technicalLimitations[]` *(native)* | `ai_limitation` *(lossy — joined, 0..1)* | `model.card.technicalLimitations[]` |
| Performance trade-offs | `modelCard.considerations.performanceTradeoffs[]` *(native)* | — | `model.card.performanceTradeoffs[]` |
| Ethical considerations | `modelCard.considerations.ethicalConsiderations[].{name, mitigationStrategy}` *(native)* | — *(lossy: free text only)* | `model.card.ethicalRisks[]` |
| Fairness assessments | `modelCard.considerations.fairnessAssessments[].{groupAtRisk, benefits, harms, mitigationStrategy}` *(native)* | — *(lossy — no SPDX home; documented one-directional loss)* | `model.card.fairness[]` |
| Energy | `modelCard.considerations.environmentalConsiderations.energyConsumptions[].{activity, activityEnergyCost{value, unit}, co2CostEquivalent{value, unit}}` — `activity` enum per schema; energy `unit` fixed `"kWh"`, CO2 `unit` fixed `"tCO2eq"` *(native)* | `ai_energyConsumption.ai_{training,finetuning,inference}EnergyConsumption[].{ai_energyQuantity, ai_energyUnit}` (`kilowattHour \| megajoule \| other`) — activities outside training/fine-tuning/inference *(lossy: dropped)* | `model.card.energy[]` |
| Safety risk | `modelCard.properties[]` `airom:model.safetyRisk` *(prop)* | `ai_safetyRiskAssessment` (`serious \| high \| medium \| low`) *(native)* | `model.card.safetyRisk` |
| Uses sensitive PII (`TriState`) | `airom:model.usesSensitivePII` (`"yes"` / `"no"`; Unknown → property omitted) *(prop)* | `ai_useSensitivePersonalInformation` — `PresenceType` (`yes \| no \| noAssertion`); Unknown → `noAssertion` *(native)* | `model.card.usesSensitivePII` |
| Training info | `airom:model.trainingInfo` *(prop)* | `ai_informationAboutTraining` *(native)* | `model.card.trainingInfo` |

### 3.5 `DataFacet` (kinds `dataset`, `prompt`)

`DataFacet`'s Go enumeration follows the research model and becomes authoritative when
`pkg/airom` lands (this scaffolding phase); the spec homes below are fixed now.

| Internal | CycloneDX 1.6 | SPDX 3.0.1 (v2) | Native JSON |
|---|---|---|---|
| Data kind | `data[].type` — `dataset` for datasets, `other` for prompts, `configuration` for `ai-config` (§4) *(native)* | — (implicit in element class) | `data.kind` |
| Dataset types (text, image, …) | `properties[]` `airom:dataset.types` (comma-joined) *(prop)* | `dataset_datasetType[]` — **required 1..\***: unknown → enum value `noAssertion` *(native)* | `data.datasetTypes[]` |
| Contents URL | `data[].contents.url` *(native)* | `software_downloadLocation` | `data.contentsUrl` |
| Size (bytes, `OptInt64`) | `airom:dataset.size` *(prop)* | `dataset_datasetSize` | `data.sizeBytes` (tri-state) |
| Classification | `data[].classification` *(native; free string)* | `dataset_confidentialityLevel` (`red \| amber \| green \| clear`) *(lossy — mapped, unmappable values dropped)* | `data.classification` |
| Sensitive data | `data[].sensitiveData[]` *(native)* | — | `data.sensitiveData[]` |
| Sensitive PII (`TriState`) | `airom:dataset.usesSensitivePII` *(prop; as §3.4 rule)* | `dataset_hasSensitivePersonalInformation` (`PresenceType`) *(native)* | `data.usesSensitivePII` |
| Collection process | `airom:dataset.collectionProcess` *(prop)* | `dataset_dataCollectionProcess` | `data.collectionProcess` |
| Intended use | `airom:dataset.intendedUse` *(prop)* | `dataset_intendedUse` | `data.intendedUse` |
| Known bias | `airom:dataset.knownBias` *(prop; `\|`-joined)* | `dataset_knownBias[]` | `data.knownBias[]` |
| Preprocessing | `airom:dataset.preprocessing` *(prop; `\|`-joined)* | `dataset_dataPreprocessing[]` | `data.preprocessing[]` |
| Anonymization | `airom:dataset.anonymization` *(prop; `\|`-joined)* | `dataset_anonymizationMethodUsed[]` | `data.anonymization[]` |
| Availability | `airom:dataset.availability` *(prop)* | `dataset_datasetAvailability` (`clickthrough \| directDownload \| query \| registration \| scrapingScript`) | `data.availability` |
| Noise / update mechanism | `airom:dataset.noise`, `airom:dataset.updateMechanism` *(prop)* | `dataset_datasetNoise`, `dataset_datasetUpdateMechanism` | `data.noise`, `data.updateMechanism` |
| Governance (custodians/stewards/owners) | `data[].governance.{custodians[], stewards[], owners[]}` *(native)* | feeds `originatedBy` / `suppliedBy` | `data.governance` |
| Originated by (`*Party`) | via governance owners *(lossy)* | `originatedBy` — **required on `dataset_DatasetPackage`**: nil → `NoAssertionElement` | `data.originatedBy` |
| Built time (`OptTime`) | `airom:dataset.builtTime` *(prop)* | `builtTime` — **required**: tri-state rule §6.4 | `data.builtTime` (tri-state) |

SARIF carries no `DataFacet` fields (— for the whole table): datasets and prompts surface in
SARIF only through their occurrences (§3.8), like every other kind.

### 3.6 `InfraFacet` (kinds `infra`, `service`) and `PackageFacet` (kinds `framework`, `library`)

Neither facet is field-enumerated in ARCHITECTURE §5; enumerations land with `pkg/airom`
(this scaffolding phase) and this section gains field-level rows in the same PR. The fixed
contract now:

| Facet | CycloneDX 1.6 | SPDX 3.0.1 (v2) | Native JSON |
|---|---|---|---|
| `InfraFacet` | endpoint URL → `properties[]` `airom:service.endpoint` *(prop; registered now)*; remaining fields → the reserved `airom:infra.*` prefix (§6.5) | `software_Package` per §4; fields → element `comment` *(lossy)* | `infra.*` |
| `PackageFacet` | ecosystem/name/version project into the `purl` (§6.3) and native CDX `name`/`group`/`version`; overflow (e.g. dependency scope) → reserved `airom:package.*` prefix (§6.5) | `software_Package` with `software_primaryPurpose` per §4 | `package.*` |

### 3.7 `BoundParam` — generation parameters with provenance (§9.5)

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `Name` + `Value` | owning component `properties[]`: name `airom:param.<Name>`, value `"<Value> @ <Path>:<Line>"` *(prop)*. Two call sites with different temperatures are **two property entries** — CDX allows duplicate names by design; values are never merged or averaged | — *(lossy — see §3.3 GenerationParams)* | — (the binding call site already appears as a result via its Occurrence) | `model.generationParams[].{name, value}` |
| `Occurrence` (`*Occurrence`) | encoded only as the `@ <Path>:<Line>` suffix *(lossy: detector, snippet, symbol dropped)* | — | — | `model.generationParams[].occurrence` *(native, full)* |

The same `airom:param.<name>` keys appear on standalone `ai-config` components (unbound
params, §9.5 refusal policy) — there the owning component is the `ai-config` `data` component
and no `@ path:line` suffix is dropped because the occurrence is also the component's own
evidence.

### 3.8 `Occurrence` (and its `Location`)

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `Location.Path` (source-root-relative, forward slashes) | `evidence.occurrences[].location` *(native; required by schema)* | — | `locations[].physicalLocation.artifactLocation.{uri, uriBaseId: "SRCROOT"}` *(native)* | `location.path` |
| `Location.Line` (1-based; 0 = whole-file) | `evidence.occurrences[].line` (schema minimum 0; AIROM emits the 1-based value; **whole-file sightings omit `line`**) | — | `region.startLine` (1-based, native convention); whole-file sightings omit `region` entirely | `location.line` |
| `Location.EndLine` | — *(lossy — CDX occurrences carry no end line)* | — | `region.endLine` | `location.endLine` |
| `Location.Column` / `EndColumn` (1-based UTF-16 code units) | — *(lossy — CDX `offset` is not a column; left unused)* | — | `region.startColumn` / `region.endColumn` under `columnKind: "utf16CodeUnits"` (§7) | `location.column`, `location.endColumn` |
| `Location.Layer` (OCI layer digest; v2 fills, §16.3) | — *(lossy)* | — | — *(reserved: v2 adds `result.properties["airom:layer"]`)* | `location.layer` |
| `DetectorID` | — *(lossy at occurrence granularity; method-level attribution survives via `evidence.identity[].methods[]`)* | — | `results[].ruleId` + `ruleIndex` → `tool.driver.rules[].id` *(native — one rule per detector, §7.3)* | `detectorId` |
| `Method` | aggregated into `evidence.identity[].methods[].technique` (§3.9, §5) | — | `tool.driver.rules[].properties["airom:method"]` *(prop; a detector has exactly one method)* | `method` |
| `Confidence` (this sighting alone) | aggregated into `evidence.identity[].methods[].confidence` | — | `result.properties["airom:occurrence.confidence"]` *(prop)* | `confidence` |
| `Snippet` (≤200 bytes, sanitized) | `evidence.occurrences[].additionalContext` *(native — the schema's designated home for matched content)* | — | `region.snippet.text` *(native)* | `snippet` |
| `Symbol` (enclosing func/class) | `evidence.occurrences[].symbol` *(native)* | — | `locations[].logicalLocations[].name` *(native)* | `symbol` |
| `Fields` (extracted bindings map) | — *(lossy — the map itself is dropped; promoted values resurface as `airom:param.*`, §3.7)* | — | — | `fields` *(native)* |

### 3.9 `IdentityClaim` — contested identity, preserved (§9.2)

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `Field` (`name \| version \| purl \| hash`) | `evidence.identity[].field` *(native — AIROM's four values are a strict subset of the CDX enum `group \| name \| version \| purl \| cpe \| omniborId \| swhid \| swid \| hash`)* | — | — | `evidence.identity[].field` |
| `Value` | `evidence.identity[].concludedValue` *(native)* | — | — | `evidence.identity[].value` |
| `Confidence` | `evidence.identity[].confidence` *(native; number 0–1, format §6.2)* | — | — | `evidence.identity[].confidence` |
| `Methods` (`[]DetectionMethod`) | `evidence.identity[].methods[]` — one entry per method: `{technique: <§5 table>, confidence: <the claim's confidence>}`; `config-analysis` additionally sets `methods[].value: "config-analysis"` (§5 recovery marker) | — | — | `evidence.identity[].methods[]` |

Winner/loser discipline: the **winning** claim per field also populates the component's
top-level `name` / `version` / `purl`; **losing** claims appear *only* as additional
`evidence.identity[]` entries — competing identity is spec-modeled in CDX and never silently
discarded (ARCHITECTURE §9.2). SPDX and SARIF carry only the winners *(lossy)*.

### 3.10 `Relationship` — typed, evidenced edges

Per-format encodings (ARCHITECTURE §11):

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `From` | `dependencies[].ref` (for `depends-on`) / the property-owning component (all other types) / the modelCard-owning component (`trained-on`) | `Relationship.from` | — | `relationships[].from` |
| `To` | `dependencies[].dependsOn[]` / property value / `modelCard.modelParameters.datasets[].ref` | `Relationship.to[]` | — | `relationships[].to` |
| `Type` | route selector (table below) | `Relationship.relationshipType` | — | `relationships[].type` |
| `Confidence` | `depends-on`, `trained-on`: — *(lossy)*; `airom:rel.*` routes: encoded in the value (`@<confidence>` suffix) *(prop)* | — *(lossy)* | — | `relationships[].confidence` |
| `Evidence` (`[]Occurrence` — the call site proving the edge) | — *(lossy in all three external formats; native only)* | — | — | `relationships[].evidence[]` |

Per-`RelType` routing:

| `RelType` | CycloneDX 1.6 route | SPDX 3.0.1 `relationshipType` (v2) |
|---|---|---|
| `depends-on` | `dependencies[]` `{ref: From, dependsOn: [To…]}` *(native)*; root edges form the `metadata.component` dependency entry | `dependsOn` |
| `trained-on` | `modelCard.modelParameters.datasets[].ref` = To (the `data` component's `bom-ref`) *(native)* | `trainedOn` |
| `contains` | `airom:rel.contains` *(prop, lossy — see format below)* | `contains` |
| `uses` | `airom:rel.uses` *(prop, lossy)* | `other` + comment `airom:uses` |
| `served-by` | `airom:rel.served-by` *(prop, lossy)* | `other` + comment `airom:served-by` |
| `queries` | `airom:rel.queries` *(prop, lossy)* | `other` + comment `airom:queries` |
| `embeds-with` | `airom:rel.embeds-with` *(prop, lossy)* | `other` + comment `airom:embeds-with` |
| `prompted-by` | `airom:rel.prompted-by` *(prop, lossy)* | `hasInput` ▲ (a prompt is an input artifact of the model) |
| `derived-from` | `airom:rel.derived-from` *(prop, lossy)* | `descendantOf` ▲ |
| `configures` | `airom:rel.configures` *(prop, lossy)* | `configures` ▲ |

**`airom:rel.*` property format** (until CycloneDX grows typed relationships): emitted on the
**From** component; property name `airom:rel.<type>`; value `"<To-bom-ref>@<confidence>"`
(e.g. `airom:rel.served-by` = `"airom:1a2b3c4d5e6f7788@0.9"`). Multiple edges of one type from
one component → duplicate property names (CDX permits duplicates). Lossy: edge `Evidence`
occurrences are dropped; type, endpoints, and confidence round-trip. The Phase 8 test parses
these properties back and asserts graph equality modulo edge evidence.

### 3.11 `Unknown` — honesty over silence (P6)

| Internal (§5) | CycloneDX 1.6 | SPDX 3.0.1 (v2) | SARIF 2.1.0 | Native JSON |
|---|---|---|---|---|
| `Path` | — *(lossy: only the count survives, `airom:unknowns` on `metadata.properties`)* | — | `runs[].invocations[].toolExecutionNotifications[].locations[].physicalLocation.artifactLocation.uri` | `unknowns[].path` |
| `DetectorID` | — | — | `…toolExecutionNotifications[].properties["airom:detectorId"]` *(prop)* | `unknowns[].detectorId` |
| `Reason` | — | — | `…toolExecutionNotifications[].message.text` (`level: "note"`) | `unknowns[].reason` |

The single SARIF invocation object carries `executionSuccessful: true` (a completed scan with
Unknowns is a successful scan — P6) alongside `endTimeUtc` (§3.1).

---

## 4. `ComponentKind` mapping

SARIF never varies its shape by kind: kind is **rule metadata only** — it influences which
rule (detector) reported the occurrence and is carried verbatim in
`result.properties["airom:kind"]`; it never affects `level` or `kind` on the result (§7.1).

| `ComponentKind` | CDX `component.type` | CDX `modelCard` | CDX `data[].type` | SPDX 3.0.1 class (v2) | SPDX `software_primaryPurpose` |
|---|---|---|---|---|---|
| `hosted-llm` | `machine-learning-model` | yes (rule §3.3) | — | `ai_AIPackage` | `model` |
| `local-model-file` | `machine-learning-model` | yes | — | `ai_AIPackage` | `model` |
| `embedding-model` | `machine-learning-model` | yes | — | `ai_AIPackage` | `model` |
| `framework` | `framework` | never | — | `software_Package` | `framework` |
| `library` | `library` | never | — | `software_Package` | `library` |
| `vector-db` | `application` (exact kind via `airom:kind`) | never | — | `software_Package` | `application` |
| `prompt` | `data` | never | `other` | `software_Package` | `data` |
| `dataset` | `data` | never | `dataset` | `dataset_DatasetPackage` | `data` |
| `ai-config` | `data` | never | `configuration` | `software_Package` | `configuration` |
| `infra` | `application` | never | — | `software_Package` | `application` |
| `service` | `application` (see note) | never | — | `software_Package` | `application` |
| `rag-pipeline` | `application` (composite; members via `airom:rel.contains`) | never | — | `software_Package` + `contains` relationships | `application` |
| `application` (scan root) | `application` — emitted as `metadata.component`, not in `components[]` | never | — | `software_Package`, `software_Sbom.rootElement` | `application` |

**Why `service` is not a CDX `services[]` entry:** CycloneDX has a native `services[]` array,
but service objects carry no `evidence` — and evidence is AIROM's non-negotiable
differentiator (P5, §1 of ARCHITECTURE). v1 therefore emits `KindService` as a component
(`type: "application"`, `airom:kind: "service"`, endpoint in `airom:service.endpoint`) so its
occurrences survive. Dual-emission into `services[]` is a possible future addition, not a v1
concern.

Coarsening note: five kinds (`vector-db`, `infra`, `service`, `rag-pipeline`, and root
`application`) share CDX type `application`; three kinds share type `data`. The exact kind is
always recoverable from the mandatory `airom:kind` property — this is what the Phase 8
CDX re-parse asserts.

---

## 5. `DetectionMethod` ↔ CycloneDX evidence technique

The mapping is **1:1 by design** (injective): every `DetectionMethod` maps to exactly one
distinct CDX `technique`, and no two methods share a target. Seven of eight are the identical
string; `config-analysis` is the one AIROM method with no same-named CDX enum value.

| `DetectionMethod` (§5) | CDX `evidence.identity[].methods[].technique` | Notes |
|---|---|---|
| `source-code-analysis` | `source-code-analysis` | identical |
| `ast-fingerprint` | `ast-fingerprint` | identical |
| `manifest-analysis` | `manifest-analysis` | identical |
| `binary-analysis` | `binary-analysis` | identical (magic bytes + header parse) |
| `hash-comparison` | `hash-comparison` | identical; the only v1 path to confidence 1.0 (§9.3) |
| `config-analysis` | `other` | CDX enum has no config-analysis value. Recovery marker: the method entry sets `value: "config-analysis"`, so the Phase 8 re-parse recovers the exact method |
| `filename` | `filename` | identical |
| `attestation` | `attestation` | identical; v2 verification (§16.2) is the other path to 1.0 |

Unused CDX enum values: `instrumentation` and `dynamic-analysis` are reserved for the v2
runtime-probing mode (ARCHITECTURE §16.8) and are never emitted in v1; `other` is reserved
exclusively as the `config-analysis` carrier so the mapping stays injective.

---

## 6. Conventions

### 6.1 Lines and columns (D18)

- **Lines are 1-based** everywhere internally (SARIF convention). `0` means
  unknown / whole-file.
- **Columns are 1-based UTF-16 code units**; SARIF output declares
  `columnKind: "utf16CodeUnits"` so this is spec-exact. `0` = unknown → column fields omitted.
- CycloneDX `evidence.occurrences[].line` has schema `minimum: 0`; AIROM emits the 1-based
  value unchanged and **omits** `line` for whole-file sightings (never emits `0`, which a
  consumer could misread as a real line under a 0-based assumption).
- SARIF: whole-file sightings emit a `physicalLocation` with `artifactLocation` only — no
  `region`.

### 6.2 Confidence

- Internal: `Confidence float64`, 0..1, produced only by the assembler's grouped noisy-OR
  (§9.3); clamped at 0.99 except hash-comparison / verified attestation (1.0).
- Serialization (deterministic, P7): round half-to-even to **4 fractional digits**, then trim
  trailing zeros — `0.9`, `0.975`, `0.8738`, `1`. CDX `confidence` fields carry that value as
  a JSON number; `airom:*` properties and SARIF property bags carry the identical textual
  form (properties are strings in CDX; numbers in SARIF bags).
- Band mapping (`high ≥ 0.9 / medium ≥ 0.6 / low`) is **presentation-only** — a UX
  convenience exposed as `Confidence.Band()` on the SDK; the table writer prints the numeric
  confidence and `--fail-on` compares it as a number, so bands are never serialized in any
  interchange format.

### 6.3 purl policy (§9.4, D9)

Spec-defined purl types only. purl is an *output* of identity, never its root.

| Kind / situation | purl |
|---|---|
| `hosted-llm`, hosted `embedding-model` | **NONE — deliberately.** Hosted API models get no purl; identity travels as `bom-ref` + `airom:model.provider` + `airom:model.id`. Minting `pkg:generic/openai/gpt-4.1` would misuse the spec and pollute purl-keyed consumers (Dependency-Track). Revisit when purl standardizes an AI type |
| HF-attributable model or dataset | `pkg:huggingface/<org>/<name>@<commit-revision>` — namespace/name lowercased, version = commit hash |
| Bare local weights file | `pkg:generic/<name>?checksum=sha256:<hex>` (content-hash identity, §9.1) |
| MLflow-registry model | `pkg:mlflow/...` |
| OCI-packaged artifact | `pkg:oci/...` |
| `framework` / `library` | ecosystem types: `pkg:pypi`, `pkg:npm`, `pkg:golang`, `pkg:maven`, `pkg:cargo`, `pkg:nuget` |
| `vector-db`, `prompt`, `ai-config`, `infra`, `service`, `rag-pipeline`, `application` | none (no spec type applies); `PURL` stays empty and the `purl` field is omitted |

### 6.4 Tri-states and the NOASSERTION discipline

Confined to the fields SPDX/CDX actually need it for (`OptString`, `OptInt64`, `OptTime`,
`TriState` — §5); not pervasive.

| State | Native JSON | SPDX 3.0.1 (v2) | CycloneDX / SARIF |
|---|---|---|---|
| `Known` | the bare value (`"version": "1.2.3"`) | the value | the value |
| `Unknown` (applies, undetermined) | JSON `null` (`"version": null`) | scalar fields → literal `"NOASSERTION"`; element references (e.g. `suppliedBy`, `originatedBy`) → the core `NoAssertionElement` individual; `PresenceType` fields → `noAssertion`; enum fields with a no-assertion member (e.g. `dataset_datasetType`) → that member | field omitted |
| `Absent` (does not apply) | field omitted | optional fields → omitted; **required** fields → coarsened to `NOASSERTION` *(lossy — the Unknown/Absent distinction survives only in native JSON)* | field omitted |

The native custom marshallers must distinguish `null` from omission in both directions; the
Phase 7 round-trip test asserts all three states survive a write→read cycle.

`TriState` (`Yes`/`No`/`Unknown`) maps to SPDX `PresenceType` `yes`/`no`/`noAssertion` and to
CDX property strings `"yes"`/`"no"`/omitted.

### 6.5 `airom:*` property namespace registry

The namespace follows CycloneDX property-taxonomy convention (registration in the official
taxonomy repo is a pre-1.0 task). **Every property any writer emits is listed here**; the
assembler rejects unregistered names in `Component.Props` (§3.2). Keys are also reused
verbatim in SARIF property bags so there is one vocabulary across formats.

Determinism (P7): properties are emitted sorted by (name, value); duplicate names are legal
and meaningful (multi-edge `airom:rel.*`, repeated `airom:param.*`).

**Document scope — CDX `metadata.properties[]`:**

| Property | Value |
|---|---|
| `airom:tool.commit` | build commit of the scanning binary |
| `airom:source.type` | `dir` \| `repo` \| `image` \| `k8s` |
| `airom:source.target` | scanned path / git URL / image reference |
| `airom:source.digest` | image digest, when applicable |
| `airom:source.git.remote` / `airom:source.git.commit` / `airom:source.git.dirty` | git provenance; dirty is `"true"`/`"false"` |
| `airom:source.k8s.context` | kube context, k8s scans only |
| `airom:unknowns` | count of `Unknown` records (lossy CDX marker; full records in native/SARIF) |

**Component scope — CDX `components[].properties[]` (and SARIF `result.properties` where §3 says so):**

| Property | Scope | Value |
|---|---|---|
| `airom:kind` | every component | exact `ComponentKind` string |
| `airom:confidence` | every component | assembled confidence (§6.2 format) |
| `airom:provider` | non-model kinds, Provider Known | normalized provider |
| `airom:model.provider` | model kinds | normalized provider (`openai`, `anthropic`, `huggingface`, `aws-bedrock`, `local`, …) |
| `airom:model.id` | model kinds | raw provider-native id, pre-normalization (e.g. `gpt-4.1-2026-01-14` when the canonical name is `gpt-4.1`) |
| `airom:model.paramCount` / `airom:model.quantization` / `airom:model.contextLength` / `airom:model.format` / `airom:model.baseModel` | model kinds | `ModelFacet` scalars with no native CDX slot (§3.3) |
| `airom:model.safetyRisk` / `airom:model.usesSensitivePII` / `airom:model.trainingInfo` | model kinds with card data | §3.4 |
| `airom:hyperparam.<key>` | `modelCard.properties[]` | training-time hyperparameters (§3.4) |
| `airom:param.<name>` | model kinds and `ai-config` components | `"<value> @ <path>:<line>"` — provenance-carrying generation params (§3.7) |
| `airom:rel.<type>` | edge-owning (From) component | `"<to-bom-ref>@<confidence>"` — non-dependency edges (§3.10) |
| `airom:conflict.<field>` | merge-demoted components | `\|`-joined conflicting Known values when a facet-field conflict demotes to Unknown (§9.2), e.g. `airom:conflict.paramCount` = `"8030261248\|8000000000"` |
| `airom:pickle.risk` / `airom:pickle.imports` | torch/pickle components | risk summary level; `\|`-joined suspicious `GLOBAL` imports (§3.3) |
| `airom:releaseTime` | any component, ReleaseTime Known | RFC 3339 (§3.2) |
| `airom:dataset.*` | `dataset` / `prompt` components | enumerated keys in §3.5: `types`, `size`, `usesSensitivePII`, `collectionProcess`, `intendedUse`, `knownBias`, `preprocessing`, `anonymization`, `availability`, `noise`, `updateMechanism`, `builtTime` |
| `airom:service.endpoint` | `service` / `infra` components | endpoint URL |
| `airom:infra.*`, `airom:package.*` | reserved prefixes | individual keys registered here when `InfraFacet` / `PackageFacet` enumerations land (§3.6) |

**SARIF-only keys (never in CDX):**

| Property | SARIF location | Value |
|---|---|---|
| `airom:componentId` | `result.properties` | the component's `airom.ID` |
| `airom:purl` | `result.properties` | component purl, when set |
| `airom:occurrence.confidence` | `result.properties` | this sighting's own confidence (component-level `airom:confidence` sits beside it) |
| `airom:method` | `tool.driver.rules[].properties` | the detector's `DetectionMethod` |
| `airom:detectorId` | `toolExecutionNotifications[].properties` | detector behind an `Unknown` (§3.11) |
| `airom:layer` | `result.properties` | **reserved for v2** per-layer attribution (§16.3) |

---

## 7. SARIF specifics

### 7.1 `level` vs `kind`

SARIF's spec-pure encoding of "this is an inventory fact, not a problem" is
`kind: "informational"` with `level` absent (§3.27.10 of the OASIS spec: any non-`fail` kind
requires `level` absent or `"none"`). However, GitHub Code Scanning and most viewers key off
`level` and render kind-only results poorly or not at all. Therefore:

- **Default:** every result emits `level: "note"` and omits `kind` (implied `fail`) —
  GitHub-compatible, annotations render.
- **`--sarif-strict-kinds`:** every result emits `kind: "informational"` and omits `level` —
  spec-pure for strict consumers.

The flag flips this one encoding globally; nothing else in the projection changes. Kind of
component, confidence, and pickle risk never escalate `level` in v1 — policy belongs in
`--fail-on`, not in the SARIF projection.

### 7.2 `partialFingerprints` recipe

```
partialFingerprints["airomComponentIdentity/v1"] =
    hex(sha256(DetectorID + "|" + ComponentID + "|" + Location.Path))
```

- `DetectorID` — the occurrence's detector (e.g. `rules/openai/model-literal`).
- `ComponentID` — the full `airom.ID` string (`airom:` prefix included).
- `Location.Path` — source-root-relative, forward slashes, exactly as in the domain model.
- Lowercase hex, full 64-character digest; literal `|` separators.
- **Line numbers are deliberately excluded** so fingerprints survive code motion; GitHub uses
  them to dedupe alerts across commits.
- The key is version-suffixed (`/v1`) per spec guidance; any change to the recipe mints
  `airomComponentIdentity/v2` rather than silently changing `/v1` semantics.

### 7.3 Rules, results, notifications

- **One rule per detector** (`tool.driver.rules[].id` = `DetectorID`) — the stable
  vocabulary. Rule metadata: `name` (UpperCamelCase derivation), `shortDescription`,
  `helpUri` (pointer into `docs/` on the repo), `defaultConfiguration.level: "note"`, and
  `properties["airom:method"]`.
- **One result per `Occurrence`** — so GitHub anchors an annotation at every sighting.
  Results reference rules by `ruleId` + `ruleIndex`.
- `message.text` (non-normative template, not contract-bound):
  `"<kind> '<group/name>' [<version>] detected (confidence <c>)"` — identity detail lives in
  the properties bag, not the prose.
- **`Unknowns` → `toolExecutionNotifications`** on the single invocation object (§3.11);
  results are reserved for actual sightings.
- Envelope constants: `$schema` = the OASIS 2.1.0 errata01 schema URI, `version: "2.1.0"`,
  `originalUriBaseIds.SRCROOT`, `columnKind: "utf16CodeUnits"`,
  `tool.driver.informationUri` = `https://github.com/Roro1727/airom`.

---

*Losses are one-directional and enumerated above: SPDX drops evidence and fairness detail;
SARIF drops model-card facets; CycloneDX drops edge evidence and per-occurrence detector
attribution. The native JSON is the superset — no writer ever needs data another writer
owns, and the Phase 7/8 tests keep it that way.*
