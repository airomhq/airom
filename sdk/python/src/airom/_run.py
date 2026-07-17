"""Running the ``airom`` binary and decoding its native JSON output."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ._binary import find_binary
from .errors import OutputError, ScanError
from .models import SCHEMA_VERSION, Inventory

__all__ = ["ScanResult", "ScanOptions", "execute", "raw"]

# Per the docs/cli.md exit-code contract: 0 = the scan completed (findings are
# NOT failures), 2 = fatal (source acquisition or configuration). Any other code
# is the user's opt-in --exit-code policy gate having matched.
EXIT_OK = 0
EXIT_FATAL = 2


@dataclass(frozen=True)
class ScanResult:
    """A completed scan.

    Attributes:
        inventory: the assembled AIBOM.
        exit_code: the process exit status.
        policy_matched: whether a ``fail_on``/``exit_code`` gate matched. A
            match is **not** an error — the scan succeeded and the inventory is
            complete; this just reports the gate's verdict.
        stderr: the tool's stderr (diagnostics, warnings).
    """

    inventory: Inventory
    exit_code: int
    policy_matched: bool
    stderr: str = ""


@dataclass(frozen=True)
class ScanOptions:
    """Options common to every scan command. ``None`` means "leave at the
    tool's default" — this SDK never invents defaults of its own.

    Size values (``max_file_size``, ``io_budget``) take the tool's ``k``/``m``/
    ``g`` suffixes, e.g. ``"512m"``.
    """

    select: str | None = None
    rules: Sequence[str] | None = None
    ignore: Sequence[str] | None = None
    min_confidence: float | None = None
    max_file_size: str | None = None
    io_budget: str | None = None
    parallel: int | None = None
    no_cache: bool = False
    cache_dir: str | None = None
    offline: bool = False
    stats: bool = False
    fail_on: str | None = None
    exit_code: int | None = None

    def to_flags(self) -> list[str]:
        """Render to argv flags, in a stable order."""
        out: list[str] = []
        if self.select is not None:
            out += ["--select", self.select]
        for r in self.rules or ():
            out += ["--rules", str(r)]
        for g in self.ignore or ():
            out += ["--ignore", str(g)]
        if self.min_confidence is not None:
            out += ["--min-confidence", repr(float(self.min_confidence))]
        if self.max_file_size is not None:
            out += ["--max-file-size", self.max_file_size]
        if self.io_budget is not None:
            out += ["--io-budget", self.io_budget]
        if self.parallel is not None:
            out += ["--parallel", str(int(self.parallel))]
        if self.no_cache:
            out += ["--no-cache"]
        if self.cache_dir is not None:
            out += ["--cache-dir", str(self.cache_dir)]
        if self.offline:
            out += ["--offline"]
        if self.stats:
            out += ["--stats"]
        if self.fail_on is not None:
            out += ["--fail-on", self.fail_on]
        if self.exit_code is not None:
            out += ["--exit-code", str(int(self.exit_code))]
        return out


def raw(
    args: Sequence[str],
    *,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``airom`` with ``args`` verbatim and return the completed process.

    The escape hatch for anything this SDK does not model. No shell is
    involved; ``args`` is passed as an argv list.
    """
    exe = find_binary(binary)
    return subprocess.run(  # noqa: S603 - argv list, no shell
        [exe, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        check=False,
    )


def execute(
    command: Sequence[str],
    *,
    options: ScanOptions | None = None,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
) -> ScanResult:
    """Run a scan command and decode its native JSON output.

    The AIBOM is written to a temporary file via ``-o json=<path>`` rather than
    read from stdout: the k8s command prints a human-readable preamble to
    stdout, so stdout is not a reliable JSON channel.

    Raises:
        ScanError: on a fatal exit (2).
        OutputError: if no parseable AIBOM was produced.
    """
    opts = options or ScanOptions()
    with tempfile.TemporaryDirectory(prefix="airom-sdk-") as tmp:
        out_path = Path(tmp) / "aibom.json"
        argv = [*command, *opts.to_flags(), "-o", f"json={out_path}"]
        proc = raw(argv, binary=binary, timeout=timeout, cwd=cwd)

        if proc.returncode == EXIT_FATAL:
            detail = (proc.stderr or proc.stdout or "").strip()
            raise ScanError(
                f"airom {' '.join(command)} failed: {detail or 'no diagnostic on stderr'}",
                exit_code=proc.returncode,
                stderr=proc.stderr or "",
            )

        if not out_path.is_file():
            raise OutputError(
                f"airom exited {proc.returncode} but wrote no AIBOM to {out_path}. "
                f"stderr: {(proc.stderr or '').strip() or '(empty)'}"
            )
        try:
            doc: dict[str, Any] = json.loads(out_path.read_text())
        except json.JSONDecodeError as e:
            raise OutputError(f"airom produced unparseable JSON: {e}") from e

    got = doc.get("schemaVersion")
    if got != SCHEMA_VERSION:
        raise OutputError(
            f"unsupported native schemaVersion {got!r}: this SDK understands "
            f"{SCHEMA_VERSION!r}. Upgrade the airom package to match your binary."
        )

    return ScanResult(
        inventory=Inventory.from_json(doc),
        exit_code=proc.returncode,
        # Exit 0 is a clean scan; 2 already raised. Anything else is the gate.
        policy_matched=proc.returncode != EXIT_OK,
        stderr=proc.stderr or "",
    )
