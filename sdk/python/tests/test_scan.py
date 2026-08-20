"""End-to-end tests: the SDK against the real binary."""

from __future__ import annotations

import pytest

import airom


def test_version(airom_binary):
    info = airom.version(binary=airom_binary)
    assert info.name == "airom"
    assert info.version  # ldflags-stamped, or "dev" for a plain `go build`


def test_fs_scan_decodes_a_real_aibom(airom_binary, ai_project):
    inv = airom.fs(str(ai_project), binary=airom_binary)

    assert inv.schema_version == airom.SCHEMA_VERSION
    assert inv.tool.name == "airom"
    assert inv.serial.startswith("urn:uuid:")
    assert inv.source.kind == "dir"
    assert inv.components, "the fixture has AI assets; expected components"

    # The scan root is an application component and is reachable via .root.
    app = inv.application
    assert app is not None and app.kind is airom.ComponentKind.APPLICATION

    # Every component carries the evidence that justifies it (the whole point).
    for c in inv.components:
        assert 0.0 <= c.confidence <= 1.0
        assert c.id.startswith("airom:")
        if c.kind is not airom.ComponentKind.APPLICATION:
            assert c.evidence.occurrences, f"{c.name} has no occurrences"


def test_finds_the_expected_kinds(airom_binary, ai_project):
    inv = airom.fs(str(ai_project), binary=airom_binary)
    names = {c.name for c in inv.components}
    assert "gpt-4.1" in names, f"hosted model not found in {sorted(names)}"

    llms = inv.by_kind(airom.ComponentKind.HOSTED_LLM)
    assert llms and any(c.name == "gpt-4.1" for c in llms)

    # by_kind accepts the raw string too.
    assert inv.by_kind("hosted-llm") == llms


def test_occurrence_points_at_file_and_line(airom_binary, ai_project):
    inv = airom.fs(str(ai_project), binary=airom_binary)
    gpt = next(c for c in inv.components if c.name == "gpt-4.1")
    occ = gpt.evidence.occurrences[0]
    assert occ.location.path == "app.py"
    assert occ.location.line > 0
    assert occ.detector_id
    assert isinstance(occ.method, airom.DetectionMethod)


def test_tristate_is_preserved(airom_binary, ai_project):
    """Absent, Unknown and Known must stay distinguishable — collapsing them
    into None would lose the SPDX NOASSERTION distinction."""
    inv = airom.fs(str(ai_project), binary=airom_binary)
    gpt = next(c for c in inv.components if c.name == "gpt-4.1")

    # A hosted model has no version in the manifest sense: the field is absent.
    assert not gpt.version.known
    assert gpt.version.or_none() is None
    assert gpt.version.or_default("-") == "-"

    # provider is known for an openai model literal.
    assert gpt.provider.known and gpt.provider.value == "openai"
    assert bool(gpt.provider) is True

    # A pinned dependency carries a known version.
    pinned = [c for c in inv.components if c.version.known]
    assert pinned, "expected at least one component with a known version"


def test_min_confidence_filters(airom_binary, ai_project):
    """--min-confidence trims findings but always keeps the application root:
    it is the scan target, not a finding, and dropping it would orphan the
    document's `root` reference."""
    everything = airom.fs(str(ai_project), binary=airom_binary)
    filtered = airom.fs(str(ai_project), binary=airom_binary, min_confidence=0.99)

    assert len(filtered.components) < len(everything.components)
    findings = [c for c in filtered.components if c.kind is not airom.ComponentKind.APPLICATION]
    assert all(c.confidence >= 0.99 for c in findings)

    # The root survives the filter regardless of its confidence.
    assert filtered.application is not None
    assert filtered.application.id == filtered.root


def test_select_narrows_detectors(airom_binary, ai_project):
    """--select tokens are detector IDs or tags, not languages."""
    inv = airom.fs(str(ai_project), binary=airom_binary, select="-manifest/npm")
    assert not any(
        o.detector_id == "manifest/npm" for c in inv.components for o in c.evidence.occurrences
    )


def test_stats_block(airom_binary, ai_project):
    inv = airom.fs(str(ai_project), binary=airom_binary, stats=True)
    assert inv.stats.files_walked > 0
    assert inv.stats.files_processed > 0


def test_cve_option_renders_flag():
    """The CVE overlay is on by default (no flag); cve=False renders --no-cve.
    Pure unit — no network, no binary."""
    assert "--no-cve" not in airom.ScanOptions().to_flags()
    assert "--cve" not in airom.ScanOptions().to_flags()
    assert "--no-cve" in airom.ScanOptions(cve=False).to_flags()


def test_fatal_error_raises_scanerror(airom_binary, tmp_path):
    with pytest.raises(airom.ScanError) as ei:
        airom.fs(str(tmp_path / "does-not-exist"), binary=airom_binary)
    assert ei.value.exit_code == 2
    assert ei.value.stderr


def test_policy_gate_is_reported_not_raised(airom_binary, ai_project):
    """A --fail-on match is a verdict, not an error: the scan succeeded and the
    inventory is complete."""
    res = airom.execute(
        ["fs", str(ai_project)],
        options=airom.ScanOptions(fail_on="hosted-llm", exit_code=7),
        binary=airom_binary,
    )
    assert res.policy_matched is True
    assert res.exit_code == 7
    assert res.inventory.components  # the AIBOM is still fully available

    clean = airom.execute(
        ["fs", str(ai_project)],
        options=airom.ScanOptions(fail_on="hosted-llm&confidence>=0.999", exit_code=7),
        binary=airom_binary,
    )
    assert clean.policy_matched is False
    assert clean.exit_code == 0


def test_missing_binary_raises_with_guidance():
    with pytest.raises(airom.BinaryNotFoundError) as ei:
        airom.fs(".", binary="/nonexistent/airom")
    assert "no such file" in str(ei.value)


def test_image_requires_a_target():
    with pytest.raises(ValueError, match="ref=|input="):
        airom.image()


def test_raw_escape_hatch(airom_binary):
    proc = airom.raw(["detectors", "list"], binary=airom_binary)
    assert proc.returncode == 0
    assert "ruleengine" in proc.stdout


def build_wheel(out_dir):
    """Build the wheel into out_dir and return its path.

    check=True with captured output raises a CalledProcessError whose repr shows
    the command and the exit status but not a byte of stderr, so a failure here
    used to read as "returned non-zero exit status 1" and nothing else — the
    reason (a missing build module) was sitting in the captured stream. Fail with
    the output instead.
    """
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "-o", str(out_dir)],
        cwd=root,
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"`python -m build --wheel` failed (exit {proc.returncode})\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    return next(Path(out_dir).glob("*.whl"))


def test_wheel_puts_airom_on_path(tmp_path):
    """`pip install airom` must give a real `airom` COMMAND, not just an
    importable library: the binary ships in the wheel's .data/scripts/, which
    pip copies into the environment's bin/. Regression test for shipping a
    wheel whose binary is only reachable via `import airom`."""
    import zipfile

    whl = build_wheel(tmp_path / "dist")
    names = zipfile.ZipFile(whl).namelist()

    scripts = [
        n for n in names
        if ".data/scripts/" in n and n.rsplit("/", 1)[-1].startswith("airom")
    ]
    assert scripts, (
        f"{whl.name} installs no airom script -> `pip install airom` would not put "
        f"`airom` on PATH. Entries: {names[:20]}"
    )
    # And it must not ALSO ship as package data: that would duplicate ~12 MB.
    assert not [n for n in names if "/_bin/" in n], "binary duplicated as package data"


def test_bundled_binary_is_version_stamped(tmp_path):
    """The wheel's binary must carry the package version, not "dev".

    ToolInfo is embedded in every AIBOM the binary emits, so an unstamped build
    makes a pip-installed airom produce documents whose provenance claims
    tool.version "dev". (hatchling gotcha: initialize()'s `version` arg is the
    build-target version, "standard"/"editable" — the package version is
    self.metadata.version.)"""
    import zipfile

    import airom as _airom

    whl = build_wheel(tmp_path / "dist")
    z = zipfile.ZipFile(whl)
    script = next(n for n in z.namelist() if ".data/scripts/" in n)

    exe = tmp_path / "airom"
    exe.write_bytes(z.read(script))
    exe.chmod(0o755)

    info = _airom.version(binary=str(exe))
    assert info.version == _airom.__version__, (
        f"wheel binary reports version {info.version!r}, expected the package version "
        f"{_airom.__version__!r} — the ldflags stamp is not being applied"
    )
    assert info.version != "dev"


def _build(args, cwd, env=None):
    import os
    import subprocess
    import sys

    return subprocess.run(
        [sys.executable, "-m", "build", *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        env={**os.environ, **(env or {})},
    )


def test_sdist_install_fails_loudly_rather_than_shipping_no_command(tmp_path):
    """`pip install airom` on a platform with no wheel must FAIL.

    pip falls back to the sdist there, and the sdist carries no binary and
    cannot build one: it does not contain the Go module. The build hook used to
    warn and continue, so the install reported success and left the user with a
    library and no scanner — a failure that surfaces much later as `airom:
    command not found`, far from its cause.

    This reproduces that path exactly: build the sdist, extract it somewhere the
    repository is not reachable, and build a wheel from it.
    """
    import tarfile
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert _build(["--sdist", "-o", str(tmp_path / "sd")], cwd=root).returncode == 0

    sdist = next((tmp_path / "sd").glob("*.tar.gz"))
    with tarfile.open(sdist) as tf:
        tf.extractall(tmp_path / "x", filter="data")
    extracted = next((tmp_path / "x").iterdir())

    # Built WITH isolation, which is what pip does for an sdist: the backend runs
    # in its own environment, exactly as it would on the user's machine.
    proc = _build(["--wheel", "-o", str(tmp_path / "out")], cwd=extracted)
    assert proc.returncode != 0, (
        "building a wheel from the sdist SUCCEEDED. That wheel installs no `airom` "
        "command, so `pip install airom` would report success and leave the user "
        f"without a scanner.\n--- stdout ---\n{proc.stdout}"
    )
    out = proc.stdout + proc.stderr
    assert "AIROM_SKIP_BUNDLE=1" in out, f"the failure does not say how to proceed:\n{out}"
    assert "releases" in out, f"the failure does not point at the binary downloads:\n{out}"


def test_skip_bundle_still_builds_a_library_only_wheel(tmp_path):
    """The refusal above must stay opt-out-able.

    Someone who already runs the standalone binary and only wants `import airom`
    has a legitimate reason to build without bundling, and the error message
    promises them this works. Assert the promise.
    """
    import tarfile
    import zipfile
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    assert _build(["--sdist", "-o", str(tmp_path / "sd")], cwd=root).returncode == 0
    sdist = next((tmp_path / "sd").glob("*.tar.gz"))
    with tarfile.open(sdist) as tf:
        tf.extractall(tmp_path / "x", filter="data")
    extracted = next((tmp_path / "x").iterdir())

    proc = _build(
        ["--wheel", "-o", str(tmp_path / "out")],
        cwd=extracted,
        env={"AIROM_SKIP_BUNDLE": "1"},
    )
    assert proc.returncode == 0, f"AIROM_SKIP_BUNDLE build failed:\n{proc.stdout}{proc.stderr}"

    whl = next((tmp_path / "out").glob("*.whl"))
    assert whl.name.endswith("py3-none-any.whl"), f"expected a pure-Python wheel, got {whl.name}"
    names = zipfile.ZipFile(whl).namelist()
    assert not [n for n in names if ".data/scripts/" in n], "opted out, but a script shipped anyway"
