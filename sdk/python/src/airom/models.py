"""Typed models for the AIROM native AIBOM (``schemaVersion: "1"``).

These mirror ``pkg/airom`` field-for-field and are decoded from the native JSON
document, which is AIROM's lossless superset format — every other output
(CycloneDX, SARIF, YAML, table) is a projection of it.

Stdlib only: the models are plain dataclasses, so importing this package pulls
in no third-party dependencies.

Tri-state fields
----------------
``version``, ``provider``, ``downloadLocation`` and ``releaseTime`` are
tri-state in AIROM, and the JSON encoding distinguishes three cases:

===============  ==================================  =======================
JSON             Meaning                             :class:`Opt`
===============  ==================================  =======================
key omitted      does not apply                      ``Presence.ABSENT``
``null``         applies, but undetermined           ``Presence.UNKNOWN``
a value          known                               ``Presence.KNOWN``
===============  ==================================  =======================

Collapsing "absent" and "null" into ``None`` would silently lose the
distinction SPDX calls NOASSERTION, so they are modelled explicitly. Use
:meth:`Opt.or_none` when you genuinely do not care.
"""

from __future__ import annotations

import datetime as _dt
import enum
import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

__all__ = [
    "Presence",
    "Opt",
    "ComponentKind",
    "DetectionMethod",
    "RelType",
    "TriState",
    "Location",
    "Occurrence",
    "IdentityClaim",
    "Evidence",
    "Hash",
    "KV",
    "License",
    "Party",
    "BoundParam",
    "PickleRisk",
    "PerformanceMetric",
    "EnergyConsumption",
    "Considerations",
    "ModelCard",
    "ModelFacet",
    "DataFacet",
    "InfraFacet",
    "PackageFacet",
    "AttestationRef",
    "Component",
    "Relationship",
    "Unknown",
    "ToolInfo",
    "GitInfo",
    "K8sInfo",
    "SourceInfo",
    "DetectorStat",
    "ScanStats",
    "Inventory",
]

T = TypeVar("T")

SCHEMA_VERSION = "1"


# ── Tri-state ────────────────────────────────────────────────────────────────


class Presence(enum.Enum):
    """Whether a tri-state field is absent, unknown, or known."""

    ABSENT = "absent"
    UNKNOWN = "unknown"
    KNOWN = "known"


@dataclass(frozen=True)
class Opt(Generic[T]):
    """A tri-state optional: absent, unknown (SPDX NOASSERTION), or known."""

    presence: Presence = Presence.ABSENT
    value: T | None = None

    @property
    def known(self) -> bool:
        """True only when a real value is present."""
        return self.presence is Presence.KNOWN

    def or_none(self) -> T | None:
        """The value if known, else ``None`` (collapses absent and unknown)."""
        return self.value if self.known else None

    def or_default(self, default: T) -> T:
        """The value if known, else ``default``."""
        return self.value if self.known else default  # type: ignore[return-value]

    def __bool__(self) -> bool:
        return self.known

    def __str__(self) -> str:
        if self.presence is Presence.KNOWN:
            return str(self.value)
        return "" if self.presence is Presence.ABSENT else "unknown"

    @classmethod
    def parse(cls, obj: dict[str, Any], key: str, conv: Callable[[Any], T]) -> Opt[T]:
        """Decode one tri-state field out of a JSON object.

        The key being missing means Absent; an explicit ``null`` means Unknown.
        """
        if key not in obj:
            return cls(Presence.ABSENT)
        raw = obj[key]
        if raw is None:
            return cls(Presence.UNKNOWN)
        return cls(Presence.KNOWN, conv(raw))


# ── Enums (open: unknown values decode to the raw string) ────────────────────


class _OpenStrEnum(str, enum.Enum):
    """A str enum that tolerates values a newer AIROM may emit."""

    @classmethod
    def _missing_(cls, value: object) -> Any:
        return str(value)


class ComponentKind(_OpenStrEnum):
    """The thirteen component kinds."""

    HOSTED_LLM = "hosted-llm"
    LOCAL_MODEL_FILE = "local-model-file"
    EMBEDDING_MODEL = "embedding-model"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    VECTOR_DB = "vector-db"
    PROMPT = "prompt"
    DATASET = "dataset"
    AI_CONFIG = "ai-config"
    INFRA = "infra"
    SERVICE = "service"
    RAG_PIPELINE = "rag-pipeline"
    APPLICATION = "application"


class DetectionMethod(_OpenStrEnum):
    """How a sighting was made. ``ATTESTATION`` is reserved for v2."""

    SOURCE_CODE_ANALYSIS = "source-code-analysis"
    AST_FINGERPRINT = "ast-fingerprint"
    MANIFEST_ANALYSIS = "manifest-analysis"
    BINARY_ANALYSIS = "binary-analysis"
    HASH_COMPARISON = "hash-comparison"
    CONFIG_ANALYSIS = "config-analysis"
    FILENAME = "filename"
    ATTESTATION = "attestation"


class RelType(_OpenStrEnum):
    """The ten relationship types."""

    USES = "uses"
    DEPENDS_ON = "depends-on"
    SERVED_BY = "served-by"
    QUERIES = "queries"
    EMBEDS_WITH = "embeds-with"
    PROMPTED_BY = "prompted-by"
    TRAINED_ON = "trained-on"
    DERIVED_FROM = "derived-from"
    CONFIGURES = "configures"
    CONTAINS = "contains"


class TriState(_OpenStrEnum):
    """A yes/no/unknown fact."""

    YES = "yes"
    NO = "no"
    UNKNOWN = "unknown"


# ── Helpers ─────────────────────────────────────────────────────────────────


# Fractional seconds in an RFC 3339 timestamp, as emitted between the seconds
# and the offset.
_FRACTION_RE = re.compile(r"\.(\d+)")


def _dt_parse(s: str) -> _dt.datetime:
    """Parse an RFC 3339 timestamp, tolerating a trailing ``Z``.

    Before Python 3.11, :meth:`datetime.fromisoformat` accepts *only* 3- or
    6-digit fractional seconds. The binary emits Go's RFC3339Nano, which prints
    nanoseconds and strips trailing zeros — so it produces 9 digits, or 7, or 1,
    and every one of those raised ``ValueError`` on the 3.10 this package
    supports.

    So normalize the fraction to exactly 6 digits before handing it over.
    :class:`datetime` resolves to microseconds regardless, so truncating (never
    rounding — a timestamp must not move) is lossless for anything it can
    represent.
    """
    t = s.strip()
    if t[-1:] in ("Z", "z"):
        t = t[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(_FRACTION_RE.sub(_micros, t, count=1))


def _micros(m: re.Match[str]) -> str:
    """Pad or truncate a fractional-second group to microsecond precision."""
    return "." + m.group(1).ljust(6, "0")[:6]


def _list(obj: dict[str, Any], key: str, conv: Callable[[Any], T]) -> list[T]:
    return [conv(x) for x in (obj.get(key) or [])]


# ── Evidence ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Location:
    """Where evidence physically sits. Lines are 1-based (0 = whole file);
    columns are 1-based UTF-16 code units (SARIF's ``columnKind``)."""

    path: str
    line: int = 0
    end_line: int = 0
    column: int = 0
    end_column: int = 0
    layer: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Location:
        return cls(
            path=o["path"],
            line=o.get("line", 0),
            end_line=o.get("endLine", 0),
            column=o.get("column", 0),
            end_column=o.get("endColumn", 0),
            layer=o.get("layer", ""),
        )


@dataclass(frozen=True)
class Occurrence:
    """One sighting of a component by one detector — the answer to
    "why is this in my AIBOM?"."""

    location: Location
    detector_id: str
    method: DetectionMethod
    confidence: float
    snippet: str = ""
    symbol: str = ""
    fields: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Occurrence:
        return cls(
            location=Location.from_json(o["location"]),
            detector_id=o["detectorId"],
            method=DetectionMethod(o["method"]),
            confidence=o["confidence"],
            snippet=o.get("snippet", ""),
            symbol=o.get("symbol", ""),
            fields=dict(o.get("fields") or {}),
        )


@dataclass(frozen=True)
class IdentityClaim:
    """A contested per-field identity claim, retained rather than discarded."""

    field_: str
    value: str
    confidence: float
    methods: list[DetectionMethod] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> IdentityClaim:
        return cls(
            field_=o["field"],
            value=o["value"],
            confidence=o["confidence"],
            methods=_list(o, "methods", DetectionMethod),
        )


@dataclass(frozen=True)
class Evidence:
    """A component's accumulated proof."""

    occurrences: list[Occurrence] = field(default_factory=list)
    identity: list[IdentityClaim] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Evidence:
        return cls(
            occurrences=_list(o, "occurrences", Occurrence.from_json),
            identity=_list(o, "identity", IdentityClaim.from_json),
        )


# ── Value types ─────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Hash:
    alg: str
    hex: str

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Hash:
        return cls(alg=o["alg"], hex=o["hex"])


@dataclass(frozen=True)
class KV:
    """An overflow property under the ``airom:*`` namespace."""

    name: str
    value: str

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> KV:
        return cls(name=o["name"], value=o["value"])


@dataclass(frozen=True)
class License:
    spdx_id: str = ""
    name: str = ""
    expression: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> License:
        return cls(
            spdx_id=o.get("spdxId", ""),
            name=o.get("name", ""),
            expression=o.get("expression", ""),
        )


@dataclass(frozen=True)
class Party:
    name: str
    url: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Party:
        return cls(name=o.get("name", ""), url=o.get("url", ""))


@dataclass(frozen=True)
class AttestationRef:
    """A discovered (v1) or verified (v2) attestation."""

    type: str
    uri: str = ""
    digest: Hash | None = None
    verified: TriState = TriState.UNKNOWN

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> AttestationRef:
        d = o.get("digest")
        return cls(
            type=o.get("type", ""),
            uri=o.get("uri", ""),
            digest=Hash.from_json(d) if d else None,
            verified=TriState(o.get("verified", "unknown")),
        )


# ── Facets ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BoundParam:
    """A generation parameter with its own provenance. Two call sites with
    different temperatures are two BoundParams — never merged, never averaged."""

    name: str
    value: str
    occurrence: Occurrence | None = None

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> BoundParam:
        occ = o.get("occurrence")
        return cls(
            name=o["name"],
            value=o["value"],
            occurrence=Occurrence.from_json(occ) if occ else None,
        )


@dataclass(frozen=True)
class PickleRisk:
    """Suspicious GLOBAL opcodes found by the static pickle walk — a security
    signal, never executed."""

    globals: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> PickleRisk:
        return cls(globals=list(o.get("globals") or []))


@dataclass(frozen=True)
class PerformanceMetric:
    type: str = ""
    value: str = ""
    slice: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> PerformanceMetric:
        return cls(type=o.get("type", ""), value=o.get("value", ""), slice=o.get("slice", ""))


@dataclass(frozen=True)
class EnergyConsumption:
    activity: str = ""
    kwh: float = 0.0

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> EnergyConsumption:
        return cls(activity=o.get("activity", ""), kwh=o.get("kWh", 0.0))


@dataclass(frozen=True)
class Considerations:
    users: list[str] = field(default_factory=list)
    use_cases: list[str] = field(default_factory=list)
    technical_limitations: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Considerations:
        return cls(
            users=list(o.get("users") or []),
            use_cases=list(o.get("useCases") or []),
            technical_limitations=list(o.get("technicalLimitations") or []),
        )


@dataclass(frozen=True)
class ModelCard:
    metrics: list[PerformanceMetric] = field(default_factory=list)
    considerations: Considerations | None = None
    energy: list[EnergyConsumption] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> ModelCard:
        c = o.get("considerations")
        return cls(
            metrics=_list(o, "metrics", PerformanceMetric.from_json),
            considerations=Considerations.from_json(c) if c else None,
            energy=_list(o, "energy", EnergyConsumption.from_json),
        )


@dataclass(frozen=True)
class ModelFacet:
    """Model-shaped data for hosted-llm, local-model-file, and embedding-model."""

    task: Opt[str] = field(default_factory=Opt)
    architecture: Opt[str] = field(default_factory=Opt)
    param_count: Opt[int] = field(default_factory=Opt)
    quantization: Opt[str] = field(default_factory=Opt)
    context_length: Opt[int] = field(default_factory=Opt)
    format: Opt[str] = field(default_factory=Opt)
    base_model: Opt[str] = field(default_factory=Opt)
    generation_params: list[BoundParam] = field(default_factory=list)
    pickle_risk: PickleRisk | None = None
    card: ModelCard | None = None

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> ModelFacet:
        pr, card = o.get("pickleRisk"), o.get("card")
        return cls(
            task=Opt.parse(o, "task", str),
            architecture=Opt.parse(o, "architecture", str),
            param_count=Opt.parse(o, "paramCount", int),
            quantization=Opt.parse(o, "quantization", str),
            context_length=Opt.parse(o, "contextLength", int),
            format=Opt.parse(o, "format", str),
            base_model=Opt.parse(o, "baseModel", str),
            generation_params=_list(o, "generationParams", BoundParam.from_json),
            pickle_risk=PickleRisk.from_json(pr) if pr else None,
            card=ModelCard.from_json(card) if card else None,
        )


@dataclass(frozen=True)
class DataFacet:
    """Dataset/prompt-shaped data."""

    format: Opt[str] = field(default_factory=Opt)
    size_bytes: Opt[int] = field(default_factory=Opt)
    url: Opt[str] = field(default_factory=Opt)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> DataFacet:
        return cls(
            format=Opt.parse(o, "format", str),
            size_bytes=Opt.parse(o, "sizeBytes", int),
            url=Opt.parse(o, "url", str),
        )


@dataclass(frozen=True)
class InfraFacet:
    """Serving-infrastructure data."""

    endpoint: Opt[str] = field(default_factory=Opt)
    region: Opt[str] = field(default_factory=Opt)
    deployment: Opt[str] = field(default_factory=Opt)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> InfraFacet:
        return cls(
            endpoint=Opt.parse(o, "endpoint", str),
            region=Opt.parse(o, "region", str),
            deployment=Opt.parse(o, "deployment", str),
        )


@dataclass(frozen=True)
class PackageFacet:
    """Framework/library package data."""

    ecosystem: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> PackageFacet:
        return cls(ecosystem=o.get("ecosystem", ""))


# ── Component & graph ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class Component:
    """One discovered AI asset: canonical identity, provenance, exactly one
    kind-family facet, assembled confidence, and the evidence behind it."""

    id: str
    kind: ComponentKind
    name: str
    confidence: float
    evidence: Evidence
    group: str = ""
    version: Opt[str] = field(default_factory=Opt)
    provider: Opt[str] = field(default_factory=Opt)
    purl: str = ""
    licenses: list[License] = field(default_factory=list)
    supplier: Party | None = None
    hashes: list[Hash] = field(default_factory=list)
    download_location: Opt[str] = field(default_factory=Opt)
    source_info: str = ""
    release_time: Opt[_dt.datetime] = field(default_factory=Opt)
    model: ModelFacet | None = None
    data: DataFacet | None = None
    infra: InfraFacet | None = None
    package: PackageFacet | None = None
    props: list[KV] = field(default_factory=list)
    attestations: list[AttestationRef] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Component:
        sup = o.get("supplier")
        return cls(
            id=o["id"],
            kind=ComponentKind(o["kind"]),
            name=o["name"],
            confidence=o["confidence"],
            evidence=Evidence.from_json(o.get("evidence") or {}),
            group=o.get("group", ""),
            version=Opt.parse(o, "version", str),
            provider=Opt.parse(o, "provider", str),
            purl=o.get("purl", ""),
            licenses=_list(o, "licenses", License.from_json),
            supplier=Party.from_json(sup) if sup else None,
            hashes=_list(o, "hashes", Hash.from_json),
            download_location=Opt.parse(o, "downloadLocation", str),
            source_info=o.get("sourceInfo", ""),
            release_time=Opt.parse(o, "releaseTime", _dt_parse),
            model=ModelFacet.from_json(o["model"]) if o.get("model") else None,
            data=DataFacet.from_json(o["data"]) if o.get("data") else None,
            infra=InfraFacet.from_json(o["infra"]) if o.get("infra") else None,
            package=PackageFacet.from_json(o["package"]) if o.get("package") else None,
            props=_list(o, "props", KV.from_json),
            attestations=_list(o, "attestations", AttestationRef.from_json),
        )

    @property
    def prop_map(self) -> dict[str, str]:
        """``props`` as a dict, for convenience."""
        return {p.name: p.value for p in self.props}


@dataclass(frozen=True)
class Relationship:
    """An evidenced, typed edge. ``from`` is a Python keyword, so the endpoints
    are exposed as ``from_id`` / ``to_id``."""

    from_id: str
    to_id: str
    type: RelType
    confidence: float
    evidence: list[Occurrence] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Relationship:
        return cls(
            from_id=o["from"],
            to_id=o["to"],
            type=RelType(o["type"]),
            confidence=o["confidence"],
            evidence=_list(o, "evidence", Occurrence.from_json),
        )


@dataclass(frozen=True)
class Unknown:
    """"Looked relevant, could not process" — honesty over silence."""

    path: str
    detector_id: str
    reason: str

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Unknown:
        return cls(path=o["path"], detector_id=o["detectorId"], reason=o["reason"])


# ── Provenance & stats ──────────────────────────────────────────────────────


@dataclass(frozen=True)
class ToolInfo:
    name: str
    version: str
    commit: str = ""

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> ToolInfo:
        return cls(name=o["name"], version=o["version"], commit=o.get("commit", ""))


@dataclass(frozen=True)
class GitInfo:
    remote: str = ""
    commit: str = ""
    branch: str = ""
    dirty: bool = False

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> GitInfo:
        return cls(
            remote=o.get("remote", ""),
            commit=o.get("commit", ""),
            branch=o.get("branch", ""),
            dirty=o.get("dirty", False),
        )


@dataclass(frozen=True)
class K8sInfo:
    context: str = ""
    namespaces: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> K8sInfo:
        return cls(context=o.get("context", ""), namespaces=list(o.get("namespaces") or []))


@dataclass(frozen=True)
class SourceInfo:
    """What was scanned."""

    kind: str
    target: str
    image_digest: str = ""
    git: GitInfo | None = None
    k8s: K8sInfo | None = None

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> SourceInfo:
        g, k = o.get("git"), o.get("k8s")
        return cls(
            kind=o["kind"],
            target=o["target"],
            image_digest=o.get("imageDigest", ""),
            git=GitInfo.from_json(g) if g else None,
            k8s=K8sInfo.from_json(k) if k else None,
        )


@dataclass(frozen=True)
class DetectorStat:
    id: str
    invocations: int = 0
    findings: int = 0
    ns: int = 0

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> DetectorStat:
        return cls(
            id=o["id"],
            invocations=o.get("invocations", 0),
            findings=o.get("findings", 0),
            ns=o.get("ns", 0),
        )


@dataclass(frozen=True)
class ScanStats:
    """The honesty block: what the scan looked at, skipped, and spent."""

    files_walked: int = 0
    files_processed: int = 0
    files_failed: int = 0
    header_bytes: int = 0
    content_bytes: int = 0
    duration_ns: int = 0
    selection: list[str] = field(default_factory=list)
    detectors: list[DetectorStat] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> ScanStats:
        return cls(
            files_walked=o.get("filesWalked", 0),
            files_processed=o.get("filesProcessed", 0),
            files_failed=o.get("filesFailed", 0),
            header_bytes=o.get("headerBytes", 0),
            content_bytes=o.get("contentBytes", 0),
            duration_ns=o.get("durationNs", 0),
            selection=list(o.get("selection") or []),
            detectors=_list(o, "detectors", DetectorStat.from_json),
            warnings=list(o.get("warnings") or []),
        )


# ── Inventory ───────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Inventory:
    """THE document: the assembled component graph."""

    schema_version: str
    tool: ToolInfo
    serial: str
    timestamp: _dt.datetime
    source: SourceInfo
    root: str
    components: list[Component] = field(default_factory=list)
    lifecycle: str = ""
    relationships: list[Relationship] = field(default_factory=list)
    unknowns: list[Unknown] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)

    @classmethod
    def from_json(cls, o: dict[str, Any]) -> Inventory:
        return cls(
            schema_version=o["schemaVersion"],
            tool=ToolInfo.from_json(o["tool"]),
            serial=o["serial"],
            timestamp=_dt_parse(o["timestamp"]),
            source=SourceInfo.from_json(o["source"]),
            root=o["root"],
            components=_list(o, "components", Component.from_json),
            lifecycle=o.get("lifecycle", ""),
            relationships=_list(o, "relationships", Relationship.from_json),
            unknowns=_list(o, "unknowns", Unknown.from_json),
            stats=ScanStats.from_json(o.get("stats") or {}),
        )

    # ── Convenience ──────────────────────────────────────────────────────

    def __len__(self) -> int:
        return len(self.components)

    def __iter__(self) -> Iterator[Component]:
        return iter(self.components)

    def by_kind(self, *kinds: ComponentKind | str) -> list[Component]:
        """Components of the given kind(s), in the inventory's sorted order."""
        wanted = {str(k.value) if isinstance(k, ComponentKind) else str(k) for k in kinds}
        return [c for c in self.components if str(c.kind.value) in wanted]

    def get(self, component_id: str) -> Component | None:
        """The component with this ID, or ``None``."""
        return next((c for c in self.components if c.id == component_id), None)

    @property
    def application(self) -> Component | None:
        """The scan-root application component."""
        return self.get(self.root)

    def edges_from(self, component_id: str) -> list[Relationship]:
        """Relationships originating at this component."""
        return [r for r in self.relationships if r.from_id == component_id]

    def edges_to(self, component_id: str) -> list[Relationship]:
        """Relationships pointing at this component."""
        return [r for r in self.relationships if r.to_id == component_id]
