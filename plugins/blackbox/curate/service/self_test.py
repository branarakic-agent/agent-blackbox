"""The curator self-test and auto-suspend (trust-and-threat-lab §03.2, F-020).

A curator must reach the right verdict on threats whose answer is already
known before it may sign anything. The fixed fixture set is 10 known threats
it must confirm (at the right tier), 10 known-clean targets it must reject and
2 "could not tell" cases it must leave not proven. The test runs this node's
own verdict rules (:func:`.verdicts.decide_verdict`) over those facts. No
network is involved, so a busy source can never fail it.

It runs when the service starts (when a curator joins), then once a day, and
on every beat while it is failing. A curator whose last run failed is
SUSPENDED: the beat signs nothing (no first signature, no co-signature, no
heartbeat) until a run passes. Suspending is a reduction, so it always applies
(LES-016). The state is stored in ``<curate home>/self_test.json``. The key
console and the join request read it through :class:`SelfTestStore`, and
``blackbox status`` shows it through :func:`health_items`.

Pattern: a table of fixtures (Value Objects) fed through one injected Strategy
(the verdict rule), with the result stored as a Memento.

Usage::

    result = SelfTest().check(today="2026-10-11")      # runs only when due
    if not result.passed: ...                           # suspended: sign nothing
    health_items(SelfTestStore().read())                # the status / health view
"""

from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import AbstractSet, Callable, Optional

from ...kernel import yaml_files
from ...kernel.health import HealthClass, HealthItem
from .. import keys
from ..lab import Check, Evidence, NoteCode, validate_evidence
from .verdicts import Tier, Verdict, VerdictDecision, VerdictFacts, decide_verdict

logger = logging.getLogger(__name__)

_FILE = "self_test.json"

#: The verdict rule under test. It has the same shape as :func:`.verdicts.decide_verdict`.
VerdictRule = Callable[[str, VerdictFacts, AbstractSet[str]], VerdictDecision]


@dataclass(frozen=True)
class Fixture:
    """One case whose answer is known: *identifier* with the *facts* a curator
    would have established, the *expected* verdict, and for a confirmation the
    *tier* it must carry (lab-only evidence is FLAG, a citable source is BLOCK)."""

    identifier: str
    facts: VerdictFacts
    expected: Verdict
    tier: Optional[Tier] = None


def _lab_run(seen: tuple[Check, ...] = (), notes: tuple[NoteCode, ...] = ()) -> Evidence:
    """One validated lab run where *seen* happened and every other check was answered "not seen"."""
    image = "e" * 64
    return validate_evidence({
        "job_key": f"{'d' * 64}:2:{image}", "image_sha256": image, "level": 2, "started_at": 1, "finished_at": 2,
        "contacted_hosts": [], "file_fingerprints": [],
        "observations": [{"check": check.value, "seen": check in seen} for check in Check],
        "notes": [note.value for note in notes],
    })


#: Exact never-flag entries the fixtures are judged against.
NEVER_FLAG: AbstractSet[str] = frozenset({"ioc:domain:never-flag.self-test.invalid",
                                          "ioc:url:https://never-flag.self-test.invalid/login"})


def fixtures() -> tuple[Fixture, ...]:
    """The fixed set: 10 known threats, 10 known-clean, 2 could-not-tell (22 in all)."""
    def listed(reference: str) -> VerdictFacts:
        return VerdictFacts(citable_listing=reference)

    def proven(*seen: Check) -> VerdictFacts:
        return VerdictFacts(lab=(_lab_run(seen),))

    clean = VerdictFacts(sources_clean=True, lab=(_lab_run(),))
    confirmed, rejected, unproven = Verdict.CONFIRMED, Verdict.REJECTED, Verdict.NOT_PROVEN
    return (
        Fixture("dep:npm:self-test-evil@1.0.0", listed("MAL-0000-0001"), confirmed, Tier.BLOCK),
        Fixture("dep:pypi:self-test-evil@2.0.0", listed("MAL-0000-0002"), confirmed, Tier.BLOCK),
        Fixture("ioc:domain:phish.self-test.invalid", listed("urlhaus:0000001"), confirmed, Tier.BLOCK),
        Fixture("ioc:url:https://drain.self-test.invalid/claim", listed("phishtank:0000001"), confirmed, Tier.BLOCK),
        Fixture("dep:npm:self-test-stealer@1.0.0", proven(Check.BAIT_CREDENTIAL_SENT), confirmed, Tier.FLAG),
        Fixture("dep:pypi:self-test-dropper@1.0.0", proven(Check.INSTALL_SCRIPT_RAN, Check.FILE_WRITTEN_OUTSIDE_PACKAGE),
                confirmed, Tier.FLAG),
        Fixture("skill:self-test-writer@1.0.0", proven(Check.FILE_WRITTEN_OUTSIDE_PACKAGE), confirmed, Tier.FLAG),
        Fixture("skill:self-test-clipper@1.0.0", proven(Check.CLIPBOARD_WRITTEN), confirmed, Tier.FLAG),
        Fixture("ioc:domain:bait.self-test.invalid", proven(Check.BAIT_CREDENTIAL_SENT), confirmed, Tier.FLAG),
        Fixture("ioc:url:https://wallet.self-test.invalid/connect", proven(Check.WALLET_PROMPT, Check.CLIPBOARD_WRITTEN),
                confirmed, Tier.FLAG),
        Fixture("dep:npm:self-test-clean@1.0.0", clean, rejected),
        Fixture("dep:pypi:self-test-clean@1.0.0", clean, rejected),
        Fixture("dep:npm:self-test-sso-login@3.1.0", clean, rejected),
        Fixture("skill:self-test-clean@1.0.0", clean, rejected),
        Fixture("skill:self-test-formatter@2.0.0", clean, rejected),
        Fixture("ioc:domain:shop.self-test.invalid", clean, rejected),
        Fixture("ioc:domain:docs.self-test.invalid", clean, rejected),
        Fixture("ioc:url:https://login.self-test.invalid/sso", clean, rejected),
        Fixture("ioc:domain:never-flag.self-test.invalid", listed("urlhaus:0000002"), rejected),       # exact never-flag wins
        Fixture("ioc:url:https://never-flag.self-test.invalid/login", clean, rejected),
        Fixture("dep:npm:self-test-timeout@1.0.0", VerdictFacts(lab=(_lab_run(notes=(NoteCode.DEADLINE_REACHED,)),)),
                unproven),
        Fixture("ioc:domain:cloaked.self-test.invalid",
                VerdictFacts(sources_clean=True, lab=(_lab_run(notes=(NoteCode.INCONCLUSIVE,)),)), unproven),
    )


@dataclass(frozen=True)
class SelfTestResult:
    """One run: the UTC *day*, how many of *total* fixtures *matched*, and one
    line per mismatch in *failures*. ``passed`` only when every fixture matched."""

    day: str
    matched: int
    total: int
    failures: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.total > 0 and self.matched == self.total and not self.failures

    def as_dict(self) -> dict[str, object]:
        return {"day": self.day, "matched": self.matched, "total": self.total, "failures": list(self.failures)}

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> SelfTestResult:
        return cls(day=str(data["day"]), matched=int(data["matched"]), total=int(data["total"]),   # type: ignore[arg-type]
                   failures=tuple(str(line) for line in data.get("failures") or ()))         # type: ignore[union-attr]


def run_self_test(day: str, decide: VerdictRule = decide_verdict) -> SelfTestResult:
    """Judge every fixture with *decide*. A rule that raises on a fixture fails
    that fixture: an error is never read as a pass."""
    cases = fixtures()
    failures: list[str] = []
    for case in cases:
        try:
            decision = decide(case.identifier, case.facts, NEVER_FLAG)
        except Exception as exc:   # the rule under test is untrusted here: any error is a failed case
            failures.append(f"{case.identifier}: the verdict rule failed ({type(exc).__name__})")
            continue
        if decision.verdict is not case.expected or (case.tier is not None and decision.tier is not case.tier):
            tier = f" ({decision.tier.value})" if decision.tier is not None else ""
            failures.append(f"{case.identifier}: expected {case.expected.value}, got {decision.verdict.value}{tier}")
    return SelfTestResult(day=day, matched=len(cases) - len(failures), total=len(cases), failures=tuple(failures))


class SelfTestStore:
    """The last self-test result on this machine (``<curate home>/self_test.json``), one lock, atomic write."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path

    def _file(self) -> Path:
        return self._path or (keys.curate_home() / _FILE)

    def read(self) -> Optional[SelfTestResult]:
        """The stored result; None when no run is recorded. An unreadable file
        reads as a FAILED run, so a damaged file cannot lift a suspension."""
        try:
            return SelfTestResult.from_dict(json.loads(self._file().read_text(encoding="utf-8-sig")))
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            return SelfTestResult(day="", matched=0, total=0, failures=("the stored self-test result is unreadable",))

    def record(self, result: SelfTestResult) -> None:
        with self._lock:
            yaml_files.atomic_write(self._file(), json.dumps(result.as_dict()))


class SelfTest:
    """The service's self-test. :meth:`check` runs the fixtures when a run is
    due: the first check of this process (a curator joining or restarting),
    a new day, or while the last run failed. Otherwise it returns the stored
    result. *decide* is the verdict rule under test (injected for tests)."""

    def __init__(self, store: Optional[SelfTestStore] = None, decide: VerdictRule = decide_verdict) -> None:
        self._store, self._decide, self._ran = store or SelfTestStore(), decide, False

    def check(self, today: str) -> SelfTestResult:
        held = self._store.read()
        if self._ran and held is not None and held.passed and held.day == today:
            return held
        result = run_self_test(today, self._decide)
        self._store.record(result)
        self._ran = True
        if not result.passed:
            logger.warning("blackbox curate service: self-test failed (%d of %d) — this curator is suspended",
                           result.total - result.matched, result.total)
        return result


def why_suspended(result: SelfTestResult) -> str:
    """The reason the beat gives for signing nothing ("" when *result* passed)."""
    return f"this curator is suspended: {_failure_text(result)}" if not result.passed else ""


def _failure_text(result: SelfTestResult) -> str:
    if not result.total:   # no run could be read back
        return result.failures[0] if result.failures else "no self-test result"
    first = result.failures[0] if result.failures else "no fixture matched"
    return f"its self-test failed {result.total - result.matched} of {result.total} on {result.day} (first: {first})"


def health_items(result: Optional[SelfTestResult]) -> list[HealthItem]:
    """The health item for a suspended curator; nothing when the last run passed or none ever ran."""
    if result is None or result.passed:
        return []
    return [HealthItem("operator", HealthClass.SECURITY, f"curator SUSPENDED: {_failure_text(result)}",
                       "this node signs nothing until a self-test passes — check this curator's Blackbox version and "
                       "files; the service re-tests on every beat while suspended")]
