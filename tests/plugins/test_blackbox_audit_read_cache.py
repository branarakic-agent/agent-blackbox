"""Whole-log reads are parsed once per change on disk (2026-10-22, FIX-0162).

``/api/findings`` read, deduped and sorted every findings log twice per
4-second poll (the page, then ``count_findings`` for the total) and
``/api/local-activity`` rebuilt the whole session graph from every log on every
request. The readers now go through ``log_store.cached``: one parse per
(mtime, size) change of the logs they merge.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import audit
from plugins.blackbox.audit import activity, findings, log_store


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    with log_store._read_cache_lock:
        log_store._read_cache.clear()


def _finding(identifier: str) -> dict:
    return {"identifier": identifier, "category": "dependency", "severity": "critical",
            "source": "public", "evidence": identifier, "kind": "malware"}


@pytest.fixture
def parses(monkeypatch):
    count = {"findings": 0, "activity": 0}
    real_rows, real_activity = findings._load_finding_rows, activity._build_local_activity

    def rows(files):
        count["findings"] += 1
        return real_rows(files)

    def graph(max_sessions):
        count["activity"] += 1
        return real_activity(max_sessions)
    monkeypatch.setattr(findings, "_load_finding_rows", rows)
    monkeypatch.setattr(activity, "_build_local_activity", graph)
    return count


def test_a_page_and_its_total_parse_the_logs_once(parses):
    audit.record(event="pre_tool_call", findings=[_finding("dep:npm:evil@1.0.0")],
                 detail={"tool_name": "terminal", "session_id": "s1", "tool_call_id": "c1"})

    page = audit.read_findings(limit=50)
    total = audit.count_findings()
    audit.read_findings(limit=50)

    assert (len(page), total) == (1, 1)
    assert parses["findings"] == 1


def test_a_new_finding_invalidates_the_cache(parses):
    audit.record(event="pre_tool_call", findings=[_finding("dep:npm:one@1")], detail={"tool_name": "t"})
    assert audit.count_findings() == 1

    audit.record(event="pre_tool_call", findings=[_finding("dep:npm:two@1")], detail={"tool_name": "t"})

    assert audit.count_findings() == 2
    assert parses["findings"] == 2


def test_local_activity_is_rebuilt_only_when_a_log_changes(parses):
    audit.record(event="session_start", detail={"session_id": "s1"})
    audit.record(event="pre_tool_call", findings=[_finding("dep:npm:evil@1.0.0")],
                 detail={"tool_name": "terminal", "session_id": "s1", "tool_call_id": "c1"})

    first = audit.read_local_activity()
    assert audit.read_local_activity() is first          # the same built graph, not a rebuild
    assert first["sessionCount"] >= 1 and parses["activity"] == 1

    audit.record_file_access("read_file", "/etc/passwd", "read")   # a log the graph merges

    assert audit.read_local_activity() is not first
    assert parses["activity"] == 2


def test_the_sandbox_home_has_its_own_entry():
    audit.record(event="pre_tool_call", findings=[_finding("dep:npm:real@1")], detail={"tool_name": "t"})
    with log_store.sandbox_run():
        audit.record(event="pre_tool_call", findings=[_finding("dep:npm:test@1")], detail={"tool_name": "t"})
        assert [r["identifier"] for r in audit.read_findings()] == ["dep:npm:test@1"]
    assert [r["identifier"] for r in audit.read_findings()] == ["dep:npm:real@1"]
