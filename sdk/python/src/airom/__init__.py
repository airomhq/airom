"""AIROM — the Python SDK for the AI Bill of Materials (AIBOM) scanner.

Wraps the ``airom`` binary and decodes its native JSON AIBOM — the lossless
superset every other output format projects from — into typed objects. No
third-party dependencies.

    >>> import airom
    >>> inv = airom.fs("./my-app", min_confidence=0.8)
    >>> for c in inv.by_kind(airom.ComponentKind.HOSTED_LLM):
    ...     print(c.name, c.provider.or_default("-"), c.confidence)
    ...     for occ in c.evidence.occurrences:
    ...         print("   ", occ.location.path, occ.location.line, occ.detector_id)

The binary is resolved from, in order: the ``binary=`` argument, a copy bundled
in this wheel, ``$AIROM_BINARY``, then ``airom`` on ``PATH``.

See https://github.com/airomhq/airom for the scanner itself.
"""

from __future__ import annotations

from ._run import ScanOptions, ScanResult, execute, raw
from .api import fs, image, k8s, repo, scan, version
from .errors import AiromError, BinaryNotFoundError, OutputError, ScanError
from .models import (
    KV,
    SCHEMA_VERSION,
    AttestationRef,
    BoundParam,
    Component,
    ComponentKind,
    Considerations,
    DataFacet,
    DetectionMethod,
    DetectorStat,
    EnergyConsumption,
    Evidence,
    GitInfo,
    Hash,
    IdentityClaim,
    InfraFacet,
    Inventory,
    K8sInfo,
    License,
    Location,
    ModelCard,
    ModelFacet,
    Occurrence,
    Opt,
    PackageFacet,
    Party,
    PerformanceMetric,
    PickleRisk,
    Presence,
    Relationship,
    RelType,
    ScanStats,
    SourceInfo,
    ToolInfo,
    TriState,
    Unknown,
)

__version__ = "0.1.7"

__all__ = [
    "__version__",
    "SCHEMA_VERSION",
    # API
    "scan",
    "fs",
    "repo",
    "image",
    "k8s",
    "version",
    "execute",
    "raw",
    "ScanOptions",
    "ScanResult",
    # Errors
    "AiromError",
    "BinaryNotFoundError",
    "ScanError",
    "OutputError",
    # Tri-state
    "Opt",
    "Presence",
    # Enums
    "ComponentKind",
    "DetectionMethod",
    "RelType",
    "TriState",
    # Models
    "Inventory",
    "Component",
    "Relationship",
    "Unknown",
    "Evidence",
    "Occurrence",
    "IdentityClaim",
    "Location",
    "Hash",
    "KV",
    "License",
    "Party",
    "AttestationRef",
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
    "ToolInfo",
    "GitInfo",
    "K8sInfo",
    "SourceInfo",
    "DetectorStat",
    "ScanStats",
]
