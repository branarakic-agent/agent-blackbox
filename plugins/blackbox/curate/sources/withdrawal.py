"""The source-withdrawal watcher and the 180-day address expiry (§03.3, F-007, F-022).

Once a week the curator re-checks every SOURCE-CITED confirmation with the
source it cites:

* the source withdrew it (an OSV/GHSA advisory carrying ``withdrawn``, a
  ThreatFox IOC that expired, a PhishTank entry verified "not a phish") → a
  REVOCATION proposal, first-signed through :meth:`CurateContext.sign` (by way
  of :func:`curate.verbs.propose_statement`). A revocation is a reduction, so
  once co-signed it publishes at once, never batched (LES-016);
* the source still lists it → nothing (and, for an address, a re-test: below);
* the source could not tell (network, rate limit, an answer we cannot read) →
  nothing at all. Only a definite answer acts (LES-011, LES-028).

Address-type confirmations (``ioc:domain:``, ``ioc:ip:``, ``ioc:url:``) expire
:data:`ADDRESS_EXPIRY_DAYS` after their last test, because cloud
infrastructure churns (ThreatFox's own practice). A re-test — this watcher's
re-check finding it still listed, or a newer ``tested_day`` the caller passes
(a lab re-run) — extends it; an address whose last test is older than that
with no re-test yields a :class:`CorrectionRequest`, prepared for the P5
correction path (a person signs that suppress; nothing here publishes it).

The step runs at most once per :data:`WATCH_INTERVAL_DAYS` (clock injected);
the last run day lives in ``<curate home>/sources/withdrawal_state.json``,
written temp-then-rename. The beat line that calls :meth:`WithdrawalWatcher.run`
is SVC4's.

Pattern: Strategy — one :data:`Recheck` per citing source, built by
:func:`rechecks_for` (OSV/GHSA by advisory id; any other source through its
own ``check``).

Usage::

    watcher = WithdrawalWatcher(rechecks_for(SOURCES))
    report = watcher.run(ctx, ProposalStore(), confirmations)   # ran=False when not due
    for request in report.corrections: ...                       # hand to the P5 path
    for extension in report.extensions: ...                      # persist the new tested_day
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from dataclasses import dataclass
from datetime import date, datetime, timedelta, UTC
from pathlib import Path
from typing import Callable, Mapping, Optional, Sequence

from ...kernel.signing import CuratorStatement
from .. import keys
from ..context import CurateContext
from ..proposals import Proposal, ProposalState, ProposalStore
from ..service.evidence import Lookup
from .client import HttpClient, UrllibClient
from .protocol import Source
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

#: The watcher runs at most once in this many days.
WATCH_INTERVAL_DAYS = 7
#: An address-type confirmation expires this long after its last test (ThreatFox: 6 months).
ADDRESS_EXPIRY_DAYS = 180
#: Identifier prefixes of the address types that expire.
ADDRESS_PREFIXES = ("ioc:domain:", "ioc:ip:", "ioc:url:")
#: The signed revocation's reason (``constants.REVOCATION_REASONS``).
REVOCATION_REASON = "evidence-withdrawn"
#: Why a correction is requested (the P5 verb's ``--reason``).
EXPIRY_REASON = "expired"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
_OSV_SOURCE = "osv"
_STATE_FILE = "withdrawal_state.json"
#: An advisory id goes into a URL path: OSV/GHSA/MAL ids only, never a slash or a dot-dot.
_ADVISORY_ID = re.compile(r"[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]{1,64}")
_OPEN_STATES = frozenset({ProposalState.PROPOSED, ProposalState.APPROVED})


@dataclass(frozen=True)
class CitedConfirmation:
    """A confirmation that cites an outside source: the threat ``identifier``,
    the citing ``source`` (a :class:`Source` name) and that source's
    ``reference_id``, and ``tested_day`` — the ISO day of its latest test (the
    confirmation, or a later re-test)."""

    identifier: str
    source: str
    reference_id: str
    tested_day: str

    @property
    def is_address(self) -> bool:
        return self.identifier.startswith(ADDRESS_PREFIXES)

    def expires_day(self) -> date:
        return date.fromisoformat(self.tested_day) + timedelta(days=ADDRESS_EXPIRY_DAYS)


@dataclass(frozen=True)
class CorrectionRequest:
    """An address that went :data:`ADDRESS_EXPIRY_DAYS` without a re-test: the
    input of the P5 correction verb (``--reason`` / ``--source``)."""

    identifier: str
    reason: str
    source: str
    reference_id: str
    tested_day: str


@dataclass(frozen=True)
class Extension:
    """An address re-tested *tested_day*; it now expires *expires_day* (both ISO)."""

    identifier: str
    tested_day: str
    expires_day: str


@dataclass(frozen=True)
class WithdrawalReport:
    """One run's outcome. ``ran`` — False when the step was not due (all else
    empty). ``revocations`` — proposals stored this run; ``undecided`` —
    identifiers whose source could not tell (left exactly as they were);
    ``failures`` — identifiers a revocation could not be proposed for."""

    ran: bool
    revocations: tuple[Proposal, ...] = ()
    corrections: tuple[CorrectionRequest, ...] = ()
    extensions: tuple[Extension, ...] = ()
    undecided: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()


#: One source's re-check of one confirmation: FOUND still listed, CLEAN
#: withdrawn, anything else could not tell.
Recheck = Callable[[CitedConfirmation], Lookup]
#: Signs and stores a revocation proposal for (identifier, evidence) — ``verbs.propose_statement`` by default.
Propose = Callable[[CurateContext, ProposalStore, str, str], Proposal]


def osv_recheck(client: Optional[HttpClient] = None) -> Recheck:
    """OSV/GHSA by the cited advisory id (``GET /v1/vulns/<id>``): an entry
    with a ``withdrawn`` timestamp is withdrawn; the same entry without one
    still stands; any other answer could not tell (OSV never deletes)."""
    http = client or UrllibClient()

    def recheck(confirmation: CitedConfirmation) -> Lookup:
        advisory = confirmation.reference_id
        if not _ADVISORY_ID.fullmatch(advisory):
            return Lookup.UNAVAILABLE
        answer = http.get(OSV_VULN_URL + urllib.parse.quote(advisory, safe=""), headers={})
        if not isinstance(answer, dict) or answer.get("id") != advisory:
            return Lookup.UNAVAILABLE
        withdrawn = answer.get("withdrawn")
        if withdrawn is None:
            return Lookup.FOUND
        return Lookup.CLEAN if isinstance(withdrawn, str) and withdrawn.strip() else Lookup.UNAVAILABLE

    return recheck


def source_recheck(source: Source) -> Recheck:
    """Any other source through its own ``check``: its CLEAN (ThreatFox
    expired, PhishTank "not a phish") is the withdrawal; a raising source
    could not tell."""

    def recheck(confirmation: CitedConfirmation) -> Lookup:
        try:
            status = source.check(confirmation.identifier).status
        except Exception:
            return Lookup.UNAVAILABLE
        return status if status in (Lookup.FOUND, Lookup.CLEAN) else Lookup.UNAVAILABLE

    return recheck


def rechecks_for(sources: Sequence[Source], client: Optional[HttpClient] = None) -> dict[str, Recheck]:
    """One :data:`Recheck` per source name: OSV by advisory id, the rest via ``check``."""
    return {source.name: osv_recheck(client) if source.name == _OSV_SOURCE else source_recheck(source)
            for source in sources}


def _propose_revocation(ctx: CurateContext, store: ProposalStore, identifier: str, evidence: str) -> Proposal:
    from .. import verbs   # the verbs import the whole publishing path; load it only when a revocation is due
    return verbs.propose_statement(ctx, store, kind=CuratorStatement.REVOCATION, identifier=identifier,
                                   fields={"reason": REVOCATION_REASON}, evidence=evidence)


def _utc_today() -> date:
    return datetime.now(UTC).date()


class WithdrawalWatcher:
    """The weekly step. *rechecks* — per source name (:func:`rechecks_for`);
    *today* — the injected clock; *state_path* — the last-run file;
    *propose* — how a revocation is first-signed and stored."""

    def __init__(self, rechecks: Mapping[str, Recheck], *, today: Callable[[], date] = _utc_today,
                 state_path: Optional[Path] = None, propose: Propose = _propose_revocation) -> None:
        self._rechecks = dict(rechecks)
        self._today = today
        self._state_path = state_path or (keys.curate_home() / "sources" / _STATE_FILE)
        self._propose = propose

    def due(self) -> bool:
        """True when the step has not run in the last :data:`WATCH_INTERVAL_DAYS`
        days (an unreadable state file counts as never: the run is idempotent)."""
        last = self._last_run()
        return last is None or (self._today() - last).days >= WATCH_INTERVAL_DAYS

    def run(self, ctx: CurateContext, store: ProposalStore,
            confirmations: Sequence[CitedConfirmation]) -> WithdrawalReport:
        """Re-check every confirmation once, if due; record the run day after."""
        if not self.due():
            return WithdrawalReport(ran=False)
        today = self._today()
        revocations: list[Proposal] = []
        corrections: list[CorrectionRequest] = []
        extensions: list[Extension] = []
        undecided: list[str] = []
        failures: list[str] = []
        for confirmation in confirmations:
            recheck = self._rechecks.get(confirmation.source)
            status = recheck(confirmation) if recheck is not None else Lookup.UNAVAILABLE
            if status is Lookup.CLEAN:
                proposal = self._revoke(ctx, store, confirmation)
                if proposal is None:
                    failures.append(confirmation.identifier)
                else:
                    revocations.append(proposal)
                continue
            if status is not Lookup.FOUND:
                undecided.append(confirmation.identifier)
            if not confirmation.is_address:
                continue
            if status is Lookup.FOUND:
                extensions.append(Extension(confirmation.identifier, today.isoformat(),
                                            (today + timedelta(days=ADDRESS_EXPIRY_DAYS)).isoformat()))
            elif today > confirmation.expires_day():
                corrections.append(CorrectionRequest(confirmation.identifier, EXPIRY_REASON, confirmation.source,
                                                     confirmation.reference_id, confirmation.tested_day))
        self._record_run(today)
        return WithdrawalReport(True, tuple(revocations), tuple(corrections), tuple(extensions), tuple(undecided),
                                tuple(failures))

    def _revoke(self, ctx: CurateContext, store: ProposalStore, confirmation: CitedConfirmation) -> Optional[Proposal]:
        """The open revocation proposal for this threat, or a new one; None when
        it could not be proposed (no manifest, an authority that may not revoke)."""
        for proposal in store.for_identifier(confirmation.identifier):
            if proposal.kind == CuratorStatement.REVOCATION.value and proposal.state in _OPEN_STATES:
                return proposal
        try:
            return self._propose(ctx, store, confirmation.identifier,
                                 f"withdrawn:{confirmation.source}:{confirmation.reference_id}")
        except ValueError as exc:   # VerbError included
            logger.warning("blackbox: could not propose revoking %s: %s", confirmation.identifier, exc)
            return None

    def _last_run(self) -> Optional[date]:
        try:
            return date.fromisoformat(json.loads(self._state_path.read_text(encoding="utf-8-sig"))["last_run"])
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def _record_run(self, day: date) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self._state_path, json.dumps({"last_run": day.isoformat()}))
