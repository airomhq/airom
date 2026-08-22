"""Unit tests for the decoding helpers.

These need no binary. test_scan.py covers the real thing end-to-end, but it only
caught the timestamp bug on the 3.10 leg of the matrix — the same input decodes
fine on 3.11+, where fromisoformat became lenient. A defect that shows up on one
interpreter and hides on another deserves a test that states the contract
outright.
"""

from __future__ import annotations

import datetime as _dt

import pytest

from airom.models import _dt_parse

UTC = _dt.timezone.utc


def at(micro: int, tz: _dt.tzinfo = UTC) -> _dt.datetime:
    """2026-07-17T12:05:20 with the given microsecond, for brevity below."""
    return _dt.datetime(2026, 7, 17, 12, 5, 20, micro, tzinfo=tz)


@pytest.mark.parametrize(
    ("raw", "expect"),
    [
        # Go's RFC3339Nano prints nanoseconds and strips trailing zeros, so the
        # fraction is any width from 1 to 9. Before 3.11, fromisoformat accepted
        # only 3 or 6 — every other width raised ValueError.
        ("2026-07-17T12:05:20.639213449+00:00", at(639213)),
        ("2026-07-17T12:05:20.8661829+00:00", at(866182)),
        ("2026-07-17T12:05:20.639213+00:00", at(639213)),
        ("2026-07-17T12:05:20.639+00:00", at(639000)),
        ("2026-07-17T12:05:20.5+00:00", at(500000)),
        # No fraction at all.
        ("2026-07-17T12:05:20+00:00", at(0)),
        # A trailing Z is UTC.
        ("2026-07-17T12:05:20Z", at(0)),
        ("2026-07-17T12:05:20.639213449Z", at(639213)),
    ],
)
def test_dt_parse_handles_every_fraction_width(raw: str, expect: _dt.datetime) -> None:
    assert _dt_parse(raw) == expect


def test_dt_parse_keeps_a_non_utc_offset() -> None:
    """Only a trailing Z is rewritten; a real offset must survive untouched."""
    ist = _dt.timezone(_dt.timedelta(hours=5, minutes=30))
    got = _dt_parse("2026-07-17T12:05:20.123456789+05:30")
    assert got == at(123456, ist)
    assert got.utcoffset() == _dt.timedelta(hours=5, minutes=30)


def test_dt_parse_truncates_rather_than_rounds() -> None:
    """A timestamp must never move. datetime resolves to microseconds, so the
    sub-microsecond tail is dropped, not rounded — rounding .9999995 up would
    invent a moment that did not happen."""
    assert _dt_parse("2026-07-17T12:05:20.9999999+00:00").microsecond == 999999


def test_dt_parse_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        _dt_parse("not a timestamp")


def test_scan_stats_assurance_fields():
    """The assurance block round-trips: 'no CVE check' must be visible in the SDK."""
    from airom import EnrichmentStats, ScanStats

    st = ScanStats.from_json(
        {
            "filesWalked": 10,
            "filesIgnored": 3,
            "dirsPruned": 2,
            "filesTruncated": 1,
            "confidenceModel": "evidence-weighted/1; not empirically calibrated",
            "enrichment": {
                "cve": {"enabled": True, "unchecked": 4},
                "eol": {"enabled": True, "catalogLoaded": True},
            },
        }
    )
    assert st.files_ignored == 3
    assert st.dirs_pruned == 2
    assert st.files_truncated == 1
    assert "not empirically calibrated" in st.confidence_model
    assert st.enrichment is not None
    assert st.enrichment.cve.unchecked == 4
    assert st.enrichment.eol.catalog_loaded is True

    # A pre-assurance document parses to honest defaults, not a crash.
    legacy = ScanStats.from_json({"filesWalked": 5})
    assert legacy.enrichment is None
    assert legacy.confidence_model == ""
    assert isinstance(EnrichmentStats.from_json({}), EnrichmentStats)
