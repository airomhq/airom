"""The public scanning API."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

from ._run import ScanOptions, ScanResult, execute, raw
from .errors import OutputError
from .models import Inventory, ToolInfo

__all__ = ["scan", "fs", "repo", "image", "k8s", "version", "ScanOptions", "ScanResult"]


def _common(
    select: str | None = None,
    rules: Sequence[str] | None = None,
    ignore: Sequence[str] | None = None,
    min_confidence: float | None = None,
    max_file_size: str | None = None,
    io_budget: str | None = None,
    parallel: int | None = None,
    no_cache: bool = False,
    cache_dir: str | None = None,
    offline: bool = False,
    stats: bool = False,
    fail_on: str | None = None,
    exit_code: int | None = None,
) -> ScanOptions:
    return ScanOptions(
        select=select,
        rules=rules,
        ignore=ignore,
        min_confidence=min_confidence,
        max_file_size=max_file_size,
        io_budget=io_budget,
        parallel=parallel,
        no_cache=no_cache,
        cache_dir=cache_dir,
        offline=offline,
        stats=stats,
        fail_on=fail_on,
        exit_code=exit_code,
    )


_DOC_COMMON = """
    Keyword args (all optional, mirroring the CLI flags — ``None`` leaves the
    tool's own default in place):

    * ``select`` — detector selection expression, e.g. ``"rules,+modelfile/gguf"``.
      Tokens match an exact detector ID or a tag; run ``airom detectors list``
      to see them.
    * ``rules`` — overlay rule-pack paths, merged by rule ID.
    * ``ignore`` — extra ignore globs, on top of ``.gitignore``/``.airomignore``.
    * ``min_confidence`` — drop components below this assembled confidence.
      ``0.8`` is a good high-signal filter on general-purpose trees. The
      application root is always kept: it is the scan target, not a finding.
    * ``max_file_size`` / ``io_budget`` — size caps, e.g. ``"1m"``, ``"512m"``.
    * ``parallel`` — worker count. Output is byte-identical at any value.
    * ``no_cache`` / ``cache_dir`` / ``offline`` / ``stats`` — as per the CLI.
    * ``fail_on`` / ``exit_code`` — the opt-in CI gate. A match is reported on
      :class:`ScanResult`, never raised.
    * ``binary`` — an explicit path to the ``airom`` executable.
    * ``timeout`` — seconds before the subprocess is killed.
    * ``cwd`` — working directory for the scan.
"""


def _scan(
    command: Sequence[str],
    *,
    binary: str | None,
    timeout: float | None,
    cwd: str | None,
    opts: ScanOptions,
) -> Inventory:
    return execute(command, options=opts, binary=binary, timeout=timeout, cwd=cwd).inventory


def scan(
    target: str,
    *,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    **kw: Any,
) -> Inventory:
    """Scan a target, auto-detecting its scheme.

    Detection order is: an existing local path, then a git URL, then an image
    reference. The ``dir:``, ``repo:`` and ``image:`` prefixes force it.
    """
    return _scan(["scan", target], binary=binary, timeout=timeout, cwd=cwd, opts=_common(**kw))


def fs(
    path: str,
    *,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    **kw: Any,
) -> Inventory:
    """Scan a directory tree."""
    return _scan(["fs", path], binary=binary, timeout=timeout, cwd=cwd, opts=_common(**kw))


def repo(
    target: str,
    *,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    **kw: Any,
) -> Inventory:
    """Scan a git repository.

    A remote URL is shallow-cloned with an installed ``git``; a local path is
    scanned as its worktree, and git provenance travels into the result.
    """
    return _scan(["repo", target], binary=binary, timeout=timeout, cwd=cwd, opts=_common(**kw))


def image(
    ref: str | None = None,
    *,
    input: str | None = None,
    platform: str | None = None,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    **kw: Any,
) -> Inventory:
    """Scan a container image.

    Pass ``input=`` for a saved tarball (``docker save -o img.tar <ref>``) or an
    OCI archive, or ``ref=`` for an OCI layout directory.

    .. note::
       Pulling from a live registry or the local daemon is **not wired yet** and
       fails with a clear error. Use ``input=`` or an OCI layout today.
    """
    if ref is None and input is None:
        raise ValueError("image(): pass ref= (an OCI layout path) or input= (a saved tarball)")
    cmd = ["image"]
    if ref is not None:
        cmd.append(ref)
    if input is not None:
        cmd += ["--input", input]
    if platform is not None:
        cmd += ["--platform", platform]
    return _scan(cmd, binary=binary, timeout=timeout, cwd=cwd, opts=_common(**kw))


def k8s(
    context: str | None = None,
    *,
    manifests: str | None = None,
    namespace: str | None = None,
    all_namespaces: bool = False,
    parallel_images: bool = False,
    binary: str | None = None,
    timeout: float | None = None,
    cwd: str | None = None,
    **kw: Any,
) -> Inventory:
    """Scan the images of Kubernetes workloads.

    .. note::
       Live-cluster scanning is **not wired yet**. Offline mode works today:
       pass ``manifests=`` a directory of manifest YAML and AIROM enumerates the
       workload images, then scans each one.
    """
    cmd = ["k8s"]
    if context is not None:
        cmd.append(context)
    if manifests is not None:
        cmd += ["--manifests", manifests]
    if namespace is not None:
        cmd += ["--namespace", namespace]
    if all_namespaces:
        cmd.append("--all-namespaces")
    if parallel_images:
        cmd.append("--parallel-images")
    return _scan(cmd, binary=binary, timeout=timeout, cwd=cwd, opts=_common(**kw))


_VERSION_RE = re.compile(r"^airom\s+(?P<version>\S+)")
_COMMIT_RE = re.compile(r"^\s*commit:\s*(?P<commit>\S+)", re.MULTILINE)


def version(*, binary: str | None = None, timeout: float | None = None) -> ToolInfo:
    """The version of the underlying ``airom`` binary.

    This is the same :class:`~airom.models.ToolInfo` that is embedded in every
    AIBOM the binary produces.
    """
    proc = raw(["version"], binary=binary, timeout=timeout)
    if proc.returncode != 0:
        raise OutputError(f"airom version failed: {(proc.stderr or '').strip()}")
    out = proc.stdout or ""
    m = _VERSION_RE.search(out)
    if not m:
        raise OutputError(f"could not parse 'airom version' output: {out!r}")
    c = _COMMIT_RE.search(out)
    return ToolInfo(name="airom", version=m.group("version"), commit=c.group("commit") if c else "")


for _f in (scan, fs, repo, image, k8s):
    _f.__doc__ = (_f.__doc__ or "") + _DOC_COMMON
