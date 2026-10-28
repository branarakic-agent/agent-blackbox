"""What the curator has said, as this node can verify it (Refine R2).

Builds ONE :class:`CuratorView` from root-signed key manifests and curator
statements read from both graphs:

* TRUST — a key manifest counts only when signed by a ROOT this network
  trusts (``kernel.signing.trust_anchors``); which manifest a reader acts on
  is ``community.trust.manifests``. No root = no manifest = no curator
  statement counts.
* PLACEMENT — enforcement-affecting statements (promotion, revocation, pause,
  the counted-author list) count only from the VERIFIED graph;
  advisory ones only from the COMMUNITY graph (plan §06). A statement signed
  for the wrong graph does not count.
* LATEST — per threat, the current verdict is the highest sequence, a
  terminal statement (revocation, rejection) winning ties and beating
  replays (:mod:`...kernel.signing.statement_order`).

Pattern: Value Object (:class:`CuratorView`) built by a pure function from
rows the reader fetched.

Usage (from the reader)::

    view = curator_view.build_view(manifest, verified_rows, community_rows,   # manifest: community.trust.manifests
                                   verified_graph=vm_graph, community_graph=community_graph)
    view.is_counted(author_key), view.rejected(identifier), view.revoked
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import date, timedelta
from typing import Any, AbstractSet, Iterable, Mapping, Optional

from ...kernel.signing import key_manifest, statement_order
from ...kernel.signing import Authority, allowed_kinds
from ...kernel.signing import CuratorStatement
from . import curator_statements
from .curator_statements import CuratorRecord

logger = logging.getLogger(__name__)
from .disputes import VerifiedDispute
from ...kernel.health import today_utc as _kernel_today


#: Statement types the VERIFIED authority publishes in the verified graph (plan §06);
#: the table itself is ``kernel.signing.authority``.
VERIFIED_GRAPH_KINDS = allowed_kinds(Authority.VERIFIED, in_verified_graph=True)
#: Statement types that decide a threat's verdict.
_VERDICT_KINDS = frozenset({CuratorStatement.CONFIRMATION, CuratorStatement.REJECTION, CuratorStatement.REVOCATION,
                            CuratorStatement.IN_REVIEW, CuratorStatement.DEFERRAL, CuratorStatement.DEFERRAL_LAPSED})


@dataclass(frozen=True)
class CountedAuthor:
    """One currently counted author: ``key`` (the reporter key — the
    identity), ``address`` (display), ``author_class`` (partner|established),
    ``org`` (partners: one cluster per organisation), ``expires`` (UTC day)."""

    key: str
    address: str
    author_class: str
    org: str
    expires: str


@dataclass(frozen=True)
class CuratorView:
    """Everything the curator has said that this node verified.

    ``manifest`` — the trusted key manifest (None: no curator statement
    counts). ``verdicts`` — the current verdict record per threat.
    ``counted`` — the counted authors, by reporter key (listed, unexpired).
    ``backlog`` / ``away`` — the latest backlog notice and the away notices.
    ``attestations`` — the current (highest-sequence) stage attestation per
    threat (R3-attest); readers prefer it over their local stage unless a
    terminal verdict dominates.

    Community Curation: one view is built PER AUTHORITY (``authority``), each
    from its own manifest and in its own sequence order. Readers act on the
    combination (``community.trust.combine``), whose ``manifest`` is still
    the VERIFIED authority's (the kill list and verified rules depend on it)
    and whose ``community`` field holds the community authority's own view.
    ``delisted`` — reporter keys whose latest entry says "not listed" and has
    not expired: a delisting by either authority removes the reporter.
    """

    manifest: Optional[key_manifest.KeyManifest] = None
    verdicts: Mapping[str, CuratorRecord] = field(default_factory=dict)
    counted: Mapping[str, CountedAuthor] = field(default_factory=dict)
    backlog: Optional[CuratorRecord] = None
    away: tuple[CuratorRecord, ...] = ()
    attestations: Mapping[str, CuratorRecord] = field(default_factory=dict)
    #: R10b: newest heartbeat day per curator key; the newest day any curator statement carries;
    #: True when two trusted manifests share an order with different content (SECURITY).
    heartbeats: Mapping[str, str] = field(default_factory=dict)
    last_statement_day: str = ""
    manifest_conflict: bool = False
    #: T1 (D31): a conflict at or below the manifest this reader already acted on — ignored, it
    #: cannot move the reader, but someone holding a root key signed an old order (SECURITY).
    manifest_conflict_ignored: bool = False
    #: R7b: "" | "pending" | "stale" with the day it takes effect / expired; while STALE,
    #: enforcement-RAISING statements dated after the expiry are frozen out — reductions
    #: and already-verified rules keep working.
    manifest_state: str = ""
    manifest_state_day: str = ""
    #: R7b: the day the trusted manifest expires ("" when undated) — the 30-day-ahead alarm.
    manifest_expires_day: str = ""
    #: The newest signed PAUSE's `until` day ("" = none) — enforced by the community tier.
    pause_until: str = ""
    #: KI-228: True when a page of manifests or curator statements FAILED (not when it was
    #: legitimately empty). Readers must then keep their last good stages — an empty view
    #: here would silently de-list every counted author and drop every threat to MONITOR.
    unavailable: bool = False
    #: Community Curation: which authority this view speaks for; the reporter keys it
    #: explicitly delisted; and, on a combined view, the community authority's own view.
    authority: Authority = Authority.VERIFIED
    delisted: frozenset[str] = frozenset()
    community: Optional[CuratorView] = None
    #: How many enforcement-raising statements this reader is holding back
    #: today under its daily cap (``community.trust.raising_budget``); they are
    #: admitted on the following days. Reductions are never held.
    held_raising: int = 0
    #: True when the last lookup of trust statements was cut short (a batch failed
    #: or reached its row limit): the view rests on what this node had stored.
    lookup_incomplete: bool = False

    def is_counted(self, author_key: str) -> bool:
        return author_key in self.counted

    def verdict(self, identifier: str) -> Optional[CuratorStatement]:
        record = self.verdicts.get(identifier)
        return record.kind if record else None

    def pause_active(self, today: str) -> bool:
        """A 2-of-3 signed pause (≤ 7 d) is in force today."""
        return bool(self.pause_until) and today <= self.pause_until

    def attestation(self, identifier: str) -> Optional[CuratorRecord]:
        """The curator's current stage attestation for *identifier*, if any."""
        return self.attestations.get(identifier)

    def rejected(self, identifier: str) -> bool:
        return self.verdict(identifier) is CuratorStatement.REJECTION

    @property
    def revoked(self) -> frozenset[str]:
        """Threats whose current verdict is a revocation."""
        return frozenset(i for i, r in self.verdicts.items() if r.kind is CuratorStatement.REVOCATION)


def _records(rows: Iterable[Mapping[str, Any]], manifest: key_manifest.KeyManifest, graph: str,
             allowed: AbstractSet[CuratorStatement], *, root_keys: AbstractSet[str] = frozenset(),
             curators_silent: bool = False) -> list[CuratorRecord]:
    """Verified records from one graph, keeping only the kinds this authority
    may publish there (*allowed*, from ``kernel.signing.authority``)."""
    records = []
    root_alone = 0
    for row in rows if allowed else ():
        record = curator_statements.parse_statement(row, manifest, graph=graph, root_keys=root_keys,
                                                    curators_silent=curators_silent)
        if record is None or record.kind not in allowed:
            continue
        if len(record.signers) < (manifest.threshold if record.kind.needs_quorum else 1):   # accepted root-alone
            root_alone += 1
            if root_alone > ROOT_ALONE_PER_READ:
                continue
        records.append(record)
    return records


#: R7b: the offline root alone may sign reductions after this many days without any curator heartbeat.
CURATOR_SILENCE_FOR_ROOT_DAYS = 7


#: Root-alone reductions one read may honour (review round 4: never "disable all" through the root).
ROOT_ALONE_PER_READ = 20


def _curators_silent(records: Iterable[CuratorRecord], today: str, community_readable: bool) -> bool:
    """True only when the community graph was READ, at least one heartbeat has ever
    been seen, and the newest is older than the silence window. An unreadable or
    unconfigured community graph is not silence (review round 4: a compromised root
    plus an eclipsed node must not revoke the whole corpus)."""
    if not community_readable:
        return False
    newest = max((r.day for r in records if r.kind is CuratorStatement.HEARTBEAT), default="")
    if not newest:
        return False
    try:
        return (date.fromisoformat(today) - date.fromisoformat(newest)).days > CURATOR_SILENCE_FOR_ROOT_DAYS
    except ValueError:
        return False


def _frozen_out(records: Iterable[CuratorRecord], state: str, since: str) -> list[CuratorRecord]:
    """While the manifest is STALE, enforcement-raising statements dated after its
    expiry are frozen out; reductions always apply (LES-016)."""
    if state != "stale":
        return list(records)
    return [r for r in records if not (r.kind.raises_enforcement and r.day > since)]


def build_view(manifest: Optional[key_manifest.KeyManifest], verified_rows: Iterable[Mapping[str, Any]],
               community_rows: Iterable[Mapping[str, Any]], *, verified_graph: str, community_graph: str,
               today: Optional[str] = None, manifest_conflict: bool = False,
               root_keys: AbstractSet[str] = frozenset(), community_readable: bool = False,
               authority: Authority = Authority.VERIFIED) -> CuratorView:
    """ONE authority's view from its trusted *manifest* and both graphs'
    statement rows. Each graph contributes only the kinds *authority* may
    publish there, so a community-authority view never contains a promotion
    or a revocation, whatever its keys signed."""
    if manifest is None:
        return CuratorView(manifest_conflict=manifest_conflict, authority=authority)
    day = today or _today()
    state, state_day = key_manifest.manifest_clock(manifest, day)
    in_verified = allowed_kinds(authority, in_verified_graph=True)
    in_community = allowed_kinds(authority, in_verified_graph=False)
    first_pass = _records(community_rows, manifest, community_graph, in_community)
    silent = _curators_silent(first_pass, day, community_readable)
    records = _frozen_out(_records(verified_rows, manifest, verified_graph, in_verified, root_keys=root_keys, curators_silent=silent)
                          + _records(community_rows, manifest, community_graph, in_community, root_keys=root_keys,
                                     curators_silent=silent), state, state_day)
    if authority is Authority.COMMUNITY:
        records = [r for r in records if _evidenced(r)]
    counted, delisted = _counted_authors(
        records, day, COMMUNITY_LISTING_MAX_DAYS if authority is Authority.COMMUNITY else None)
    return CuratorView(manifest=manifest, verdicts=_current_verdicts(records),
                       counted=counted, delisted=delisted, authority=authority,
                       backlog=_latest(r for r in records if r.kind is CuratorStatement.BACKLOG),
                       away=tuple(r for r in records if r.kind is CuratorStatement.AWAY),
                       attestations=_current_attestations(records),
                       heartbeats=_heartbeats(records), last_statement_day=max((r.day for r in records), default=""),
                       pause_until=_active_pause_until(records),
                       manifest_conflict=manifest_conflict, manifest_state=state, manifest_state_day=state_day,
                       manifest_expires_day=(state_day if state != "pending" else key_manifest.manifest_clock(manifest, state_day)[1]))


def _evidenced(record: CuratorRecord) -> bool:
    """A COMMUNITY confirmation counts only when it carries the signed
    reference to the evidence its curators checked (plan §05: without one the
    confirmed pool would be a list of opinions). Every other statement passes."""
    return record.kind is not CuratorStatement.CONFIRMATION or bool(record.field("evidence"))


def _heartbeats(records: Iterable[CuratorRecord]) -> dict[str, str]:
    """Newest heartbeat day per curator key (only a key beating for ITSELF counts)."""
    newest: dict[str, str] = {}
    for record in records:
        if record.kind is CuratorStatement.HEARTBEAT and record.field("key") in record.signers:
            newest[record.field("key")] = max(newest.get(record.field("key"), ""), record.day)
    return newest


def _current_verdicts(records: Iterable[CuratorRecord]) -> dict[str, CuratorRecord]:
    by_order: dict[statement_order.OrderedStatement, CuratorRecord] = {}
    for record in records:
        if record.kind in _VERDICT_KINDS:
            by_order[statement_order.OrderedStatement(record.identifier, record.kind, record.sequence)] = record
    current = statement_order.current_by_threat(by_order)
    return {threat: by_order[ordered] for threat, ordered in current.items()}


#: How much a stage enforces in the community tier — lower enforces less. Used
#: wherever two attestations must be ordered without a sequence to decide.
STAGE_ENFORCEMENT_RANK: Mapping[str, int] = {"held": 0, "deferred": 0, "reported": 1, "corroborated": 2}


def _attestation_order(record: CuratorRecord) -> tuple[int, int]:
    """Sort key: higher sequence first; at a tie the stage that enforces LESS
    wins, so the outcome never depends on which row was read first (KI-245)."""
    return record.sequence, -STAGE_ENFORCEMENT_RANK.get(record.field("stage"), 0)


def _current_attestations(records: Iterable[CuratorRecord]) -> dict[str, CuratorRecord]:
    """The highest-sequence attestation per threat: a replayed older one loses."""
    current: dict[str, CuratorRecord] = {}
    for record in records:
        if record.kind is CuratorStatement.ATTESTATION:
            held = current.get(record.identifier)
            if held is None or _attestation_order(record) > _attestation_order(held):
                current[record.identifier] = record
    return current


#: A listing signed by the COMMUNITY authority counts for at most this many
#: days from its signed day, whatever expiry it states (Community Curation
#: decision 6: its curator keys are online, so a listing is short and renewed).
COMMUNITY_LISTING_MAX_DAYS = 90


def _effective_expiry(record: CuratorRecord, max_days: Optional[int]) -> str:
    """The day a listing stops counting: its signed expiry, or *max_days*
    after its signed day when that is earlier."""
    stated = record.field("expires")
    if max_days is None:
        return stated
    try:
        capped = (date.fromisoformat(record.day) + timedelta(days=max_days)).isoformat()
    except ValueError:
        return stated
    return min(stated, capped)


def _listing_order(record: CuratorRecord) -> tuple[int, bool]:
    """Sort key: higher sequence first; at a tie a DELISTING wins, whichever
    row was read first (KI-245 — a delisting must never lose to a listing)."""
    return record.sequence, record.field("listed") == "no"


def _delisting_in_force(record: CuratorRecord, today: str) -> bool:
    """A delisting holds for as long as the longest listing it could be
    overriding (``LISTING_MAX_DAYS`` from its signed day) — bounded, so a
    reporter is never denylisted forever by one old statement."""
    try:
        age = (date.fromisoformat(today) - date.fromisoformat(record.day)).days
    except ValueError:
        return True   # an unreadable day never ends a reduction early
    return age <= curator_statements.LISTING_MAX_DAYS


def _counted_authors(records: Iterable[CuratorRecord], today: str,
                     max_days: Optional[int] = None) -> tuple[dict[str, CountedAuthor], frozenset[str]]:
    """(counted, delisted) from the latest entry per author key: *counted* —
    listed and unexpired (a listing also ends *max_days* after its signed day
    when given); *delisted* — keys whose latest entry says "not listed" and is
    still in force (it also removes the other authority's listing)."""
    latest: dict[str, CuratorRecord] = {}
    for record in records:
        if record.kind is CuratorStatement.COUNTED_AUTHORS:
            held = latest.get(record.identifier)
            if held is None or _listing_order(record) > _listing_order(held):
                latest[record.identifier] = record
    counted, delisted = {}, set()
    for identifier, record in latest.items():
        key = identifier[len("author:"):]
        expires = _effective_expiry(record, max_days)
        if record.field("listed") == "yes" and expires >= today:
            counted[key] = CountedAuthor(key=key, address=record.field("address"),
                                         author_class=record.field("class"), org=record.field("org"),
                                         expires=expires)
        elif record.field("listed") == "no" and _delisting_in_force(record, today):
            delisted.add(key)
    return counted, frozenset(delisted)


def _active_pause_until(records: Iterable[CuratorRecord]) -> str:
    """The `until` day of the pause in force, honouring §09 "not renewable back-to-back by
    the same pair" (KI-229): walking pauses in sequence order, a pause signed by the SAME
    signers as the pause it would extend, dated on or before that pause's `until`, is a
    renewal and is ignored — two keys cannot chain 7-day pauses indefinitely. A pause by
    a different signer set, or one that starts after the previous pause ended, counts."""
    active: Optional[CuratorRecord] = None
    for record in sorted((r for r in records if r.kind is CuratorStatement.PAUSE), key=lambda r: r.sequence):
        if active is not None and record.signers == active.signers and record.day <= active.field("until"):
            logger.info("blackbox: ignoring a back-to-back pause renewal by the same signers (statement #%d)", record.sequence)
            continue
        active = record
    return active.field("until") if active is not None else ""


def _latest(records: Iterable[CuratorRecord]) -> Optional[CuratorRecord]:
    return max(records, key=lambda r: r.sequence, default=None)




def counted_dispute_weight(disputes: Iterable[VerifiedDispute], view: CuratorView) -> dict[str, int]:
    """Per threat, how many COUNTED authors dispute it. An unlisted author's
    dispute weighs 0 (plan §04): it is shown, never counted toward decay."""
    disputers: dict[str, set] = {}
    for dispute in disputes:
        if view.is_counted(dispute.author):
            disputers.setdefault(dispute.identifier, set()).add(dispute.author)
    return {identifier: len(authors) for identifier, authors in disputers.items()}


def _today() -> str:
    """The clock seam (tests set it): the kernel's UTC day."""
    return _kernel_today()


def today_utc() -> str:
    """The reader's UTC day (the clock every curator-statement span uses)."""
    return _today()
