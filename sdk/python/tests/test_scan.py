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
