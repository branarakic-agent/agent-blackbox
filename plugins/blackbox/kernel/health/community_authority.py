"""Operator alarms about the COMMUNITY authority (Community Curation C10, plan §11 OBSERVE).

The community graph has its own curators (its own root, its own key manifest,
statements in the community graph itself). An operator needs to know when that
trust layer is not working, and that none of it reduces what already protects
them: these are all INFO except a manifest conflict (SECURITY).

* the trust lookup was cut short (the graph is flooded or the node is busy);
* every community curator key is silent / some keys are;
* the community key manifest is pending, stale, about to expire, or in conflict;
* raising statements are being held by this reader's own daily cap.

Facts in, alarms out: :func:`gather` reads them off the community authority's
view (duck-typed — the kernel imports no feature), :func:`alarms` turns them
into items. ``kernel.health.operator_health`` adds them to the operator's list.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional
from .days import days_between

#: A curator key without a heartbeat for longer than this is silent (plan §13: 48 hours).
HEARTBEAT_SILENCE_DAYS = 2
#: A manifest expiring within this many days is announced.
EXPIRY_NOTICE_DAYS = 30

#: (class name, message, what to do) — the caller wraps them in its HealthItem.
Alarm = tuple[str, str, str]


@dataclass(frozen=True)
class CommunityAuthorityInputs:
    """What the alarms look at. ``trusted`` — a community key manifest is
    trusted on this node; ``keys`` / ``silent_keys`` — its curator keys and how
    many have no heartbeat inside the silence window; ``last_heartbeat`` — the
    newest heartbeat day of any key ("" = never); ``manifest_state`` (""|
    "pending"|"stale"), ``manifest_state_day``, ``manifest_expires_day``,
    ``manifest_conflict``, ``manifest_conflict_ignored`` (T1: a conflict at or
    below the sticky order, ignored); ``held_raising`` — raising statements this reader is
    holding under its daily cap; ``lookup_incomplete`` — the last trust lookup
    was cut short; ``today`` — the UTC day."""

    trusted: bool = False
    keys: int = 0
    silent_keys: int = 0
    last_heartbeat: str = ""
    manifest_state: str = ""
    manifest_state_day: str = ""
    manifest_expires_day: str = ""
    manifest_conflict: bool = False
    manifest_conflict_ignored: bool = False
    held_raising: int = 0
    lookup_incomplete: bool = False
    today: str = ""



def gather(view: Optional[Any], today: str) -> CommunityAuthorityInputs:
    """The inputs from the community authority's own view (``CuratorView.community``; None = no community authority)."""
    if view is None:
        return CommunityAuthorityInputs(today=today)
    manifest = getattr(view, "manifest", None)
    keys = tuple(manifest.curator_keys) if manifest is not None else ()
    beats = dict(getattr(view, "heartbeats", {}) or {})
    silent = sum(1 for key in keys if not beats.get(key) or days_between(beats[key], today) > HEARTBEAT_SILENCE_DAYS)
    return CommunityAuthorityInputs(
        trusted=manifest is not None, keys=len(keys), silent_keys=silent,
        last_heartbeat=max((beats[key] for key in keys if beats.get(key)), default=""),
        manifest_state=str(getattr(view, "manifest_state", "") or ""),
        manifest_state_day=str(getattr(view, "manifest_state_day", "") or ""),
        manifest_expires_day=str(getattr(view, "manifest_expires_day", "") or ""),
        manifest_conflict=bool(getattr(view, "manifest_conflict", False)),
        manifest_conflict_ignored=bool(getattr(view, "manifest_conflict_ignored", False)),
        held_raising=int(getattr(view, "held_raising", 0) or 0),
        lookup_incomplete=bool(getattr(view, "lookup_incomplete", False)), today=today)


def alarms(inputs: CommunityAuthorityInputs) -> list[Alarm]:
    """The operator's alarms about the community authority, as (class, message, what to do)."""
    out: list[Alarm] = []
    if inputs.manifest_conflict:
        out.append(("security", "community curator key manifest CONFLICT: two root-signed manifests disagree",
                    "community trust is frozen at the last agreed version; verified rules are unaffected — tell the community curators"))
    if inputs.manifest_conflict_ignored:
        out.append(("security", "community curator key manifest conflict IGNORED: a root-signed list contradicts one this node already acts on",
                    "nothing changes on this node — it keeps the list it acts on; tell the community curators a root key may be compromised"))
    if inputs.lookup_incomplete:
        out.append(("info", "the community trust lookup was cut short (the graph is flooded or the node is busy)",
                    "nothing to do — this node keeps acting on the trust statements it already verified; new ones may arrive late"))
    if inputs.held_raising:
        out.append(("info", f"{inputs.held_raising} community confirmation(s) or listing(s) held by this node's daily cap",
                    "nothing to do — they are admitted over the next days, oldest first; rejections and delistings are never held"))
    if not inputs.trusted:
        return out
    if inputs.keys and inputs.silent_keys == inputs.keys:
        since = f"since {inputs.last_heartbeat}" if inputs.last_heartbeat else "(no heartbeat seen yet)"
        out.append(("info", f"the community curators are silent {since}",
                    "nothing to do — community flags in force stay; new confirmations and listings wait for the curators"))
    elif inputs.silent_keys:
        out.append(("info", f"community curator heartbeat missing for {inputs.silent_keys} of {inputs.keys} key(s)",
                    "nothing to do — two keys are enough for the curators to keep working"))
    if inputs.manifest_state == "stale":
        out.append(("info", f"community curator key manifest STALE since {inputs.manifest_state_day}",
                    "nothing to do — community flags in force stay and reductions still apply; new confirmations and listings are "
                    "frozen until the community root publishes a fresh manifest"))
    elif inputs.manifest_state == "pending":
        out.append(("info", f"a new community curator key manifest takes effect on {inputs.manifest_state_day} (time-lock)",
                    "nothing to do — the previous manifest stays in force until then"))
    if (inputs.manifest_expires_day and inputs.today   # a stale manifest's expiry is in the past: never announced twice
            and 0 <= days_between(inputs.today, inputs.manifest_expires_day) <= EXPIRY_NOTICE_DAYS):
        out.append(("info", f"the community curator key manifest expires on {inputs.manifest_expires_day}",
                    "nothing to do — the community root publishes a new one; flags in force stay either way"))
    return out
