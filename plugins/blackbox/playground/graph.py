"""The sandbox lane drawn as the dashboard's Community graph (2026-10-21).

In sandbox mode the dashboard's Community tab reads the verified graph's
``sandbox`` lane instead of ``reports``, so a member can watch its tests
propagate exactly as real warnings do. These two builders turn a
:class:`LaneView` into the same response shapes ``GET /api/graph?tier=community``
and ``GET /api/threat?tier=community`` return, so the page draws them unchanged.

Display only: nothing here reaches the rules or the community flags — protection
keeps reading the ``reports`` lane while sandbox mode is on.

Usage::

    page = graph.graph_page(view, limit=200)            # the bubble graph
    detail = graph.threat_detail(view, "ioc:domain:x")  # the threat modal
"""

from __future__ import annotations

from typing import Any

from .lane import LaneEntry, LaneView

#: Identifier prefix -> the dashboard's threat category (the same names /api/graph uses).
_CATEGORY_BY_PREFIX = {"ioc": "ioc", "dep": "dependency", "injection": "injection", "skill": "skill",
                       "fileaccess": "fileaccess", "secret": "secret", "escalation": "escalation"}
_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def category_of(identifier: str, fields: dict[str, str]) -> str:
    """The threat's category: the report's own ``category`` field when it names one, else its identifier prefix."""
    prefix = identifier.split(":", 1)[0]
    return _CATEGORY_BY_PREFIX.get(prefix) or fields.get("category") or "other"


def _threats(view: LaneView) -> list[dict[str, Any]]:
    """One bubble per threat identifier, newest first, with its distinct reporters counted."""
    grouped: dict[str, list[LaneEntry]] = {}
    for entry in view.entries:
        grouped.setdefault(entry.identifier, []).append(entry)
    threats = []
    for identifier, entries in grouped.items():
        fields = dict(entries[0].fields)
        severity = max((e.severity for e in entries), key=lambda s: _SEVERITY_RANK.get(s, -1))
        threats.append({
            "identifier": identifier, "name": identifier, "category": category_of(identifier, fields),
            "severity": severity, "reporterCount": len({e.reporter.lower() for e in entries}),
            "stage": "sandbox", "stageReason": "a sandbox test: never a flag or a rule",
            "enforcement": "none", "networkLive": "yes", "sandbox": True, "profile": {},
            "mine": any(e.mine for e in entries),
        })
    return threats


def _ecosystem(identifier: str) -> str:
    parts = identifier.split(":")
    return parts[1] if parts[0] == "dep" and len(parts) > 2 else ""


def graph_page(view: LaneView, *, q: str = "", category: str = "", ecosystem: str = "",
               offset: int = 0, limit: int = 200) -> dict[str, Any]:
    """The ``/api/graph?tier=community`` page shape, built from the sandbox lane."""
    threats = _threats(view)
    category_totals: dict[str, int] = {}
    ecosystem_totals: dict[str, int] = {}
    for threat in threats:
        category_totals[threat["category"]] = category_totals.get(threat["category"], 0) + 1
        if _ecosystem(threat["identifier"]):
            eco = _ecosystem(threat["identifier"])
            ecosystem_totals[eco] = ecosystem_totals.get(eco, 0) + 1
    wanted = [t for t in threats
              if (not q or q.lower() in t["identifier"].lower())
              and (not category or t["category"] == category)
              and (not ecosystem or _ecosystem(t["identifier"]) == ecosystem)]
    offset, limit = max(0, offset), max(1, min(limit, 1000))
    page = wanted[offset:offset + limit]
    return {"tier": "community", "sandbox": True, "readable": view.readable, "threats": page,
            "total": len(wanted), "category_totals": category_totals, "ecosystem_totals": ecosystem_totals,
            "offset": offset, "limit": limit, "partial": offset + len(page) < len(wanted)}


def threat_detail(view: LaneView, identifier: str) -> dict[str, Any]:
    """The ``/api/threat?tier=community`` detail shape for one sandbox threat (``found`` False when absent)."""
    entries = [e for e in view.entries if e.identifier == identifier]
    if not entries:
        return {"identifier": identifier, "tier": "community", "sandbox": True, "found": False}
    detail: dict[str, Any] = dict(entries[0].fields)
    reporters = sorted({e.reporter for e in entries})
    detail.update({
        "identifier": identifier, "name": identifier, "tier": "community", "source": "sandbox", "sandbox": True,
        "found": True, "severity": max((e.severity for e in entries), key=lambda s: _SEVERITY_RANK.get(s, -1)),
        "reporters": len(reporters), "reporterCount": len(reporters), "sandboxReporters": reporters,
        "stage": "sandbox", "enforcement": "none",
        "description": "A sandbox test shared to the verified graph's sandbox lane: shown here, never a flag or a rule.",
    })
    return detail

