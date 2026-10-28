"""Beta reputation with forgetting, graduation and demotion rules (R4, plan §05).

Reputation is the mean of a Beta distribution over curator outcomes: each
confirmation adds to α, each rejection to β, and every outcome fades with
age (exponential forgetting, half-life :data:`HALF_LIFE_DAYS`) so an old
record neither protects nor condemns forever. Strikes (confirmed bad faith)
are a separate counter: two demote regardless of reputation, and a demoted
reporter sits out :data:`LOCKOUT_DAYS` and then re-graduates from zero.

Pure functions only; the ledger (:mod:`.ledger`) supplies the outcomes.

Usage::

    rep = beta_reputation([Outcome("2026-09-01", True), Outcome("2026-09-20", False)], today="2026-10-02")
    graduates(standing, today)   # True when 14 days old, ≥5 novel credits, no strikes, not locked out
    demotion(standing, rep)      # a ReporterStanding with a lockout, or None
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date, timedelta
from typing import Iterable, Optional

from .bands import ReporterStanding, ReputationBand
from ...kernel.health import days_between

#: Forgetting: an outcome this many days old counts half.
HALF_LIFE_DAYS = 180.0
#: Beta prior (1, 1): a reporter with no outcomes sits at 0.5, below the floor.
PRIOR_ALPHA = 1.0
PRIOR_BETA = 1.0
#: Graduation (plan §05): 14 days AND five novel curator-confirmed reports.
GRADUATION_MIN_DAYS = 14
GRADUATION_MIN_NOVEL = 5
#: Demotion: this many strikes, or a reputation under the floor.
STRIKES_TO_DEMOTE = 2
REPUTATION_FLOOR = 0.5
LOCKOUT_DAYS = 90


@dataclass(frozen=True)
class Outcome:
    """One curator decision about one of the reporter's reports: the UTC
    ``day`` it was made and whether it ``confirmed`` the report."""

    day: str
    confirmed: bool



def beta_reputation(outcomes: Iterable[Outcome], today: str) -> float:
    """α / (α + β) over the outcomes, each weighted 0.5 ** (age / half-life)."""
    alpha, beta = PRIOR_ALPHA, PRIOR_BETA
    for outcome in outcomes:
        weight = 0.5 ** (max(0.0, days_between(outcome.day, today)) / HALF_LIFE_DAYS)
        if outcome.confirmed:
            alpha += weight
        else:
            beta += weight
    return alpha / (alpha + beta)


def graduates(standing: ReporterStanding, today: str) -> bool:
    """Probation → established: old enough, enough NOVEL confirmed reports,
    no strike on record and no lockout running."""
    if standing.band is not ReputationBand.PROBATION or standing.locked_out(today) or not standing.first_seen_day:
        return False
    return (days_between(standing.first_seen_day, today) >= GRADUATION_MIN_DAYS
            and standing.novel_credits >= GRADUATION_MIN_NOVEL and standing.strikes == 0)


def demotion(standing: ReporterStanding, reputation: float, today: str) -> Optional[ReporterStanding]:
    """The locked-out standing when *standing* must leave its band (strikes
    reached, or reputation under the floor), else None. A lockout resets
    every counter: re-graduation starts from zero."""
    if standing.band is ReputationBand.PROBATION:
        return None
    if standing.strikes < STRIKES_TO_DEMOTE and reputation >= REPUTATION_FLOOR:
        return None
    until = (date.fromisoformat(today) + timedelta(days=LOCKOUT_DAYS)).isoformat()
    return replace(standing.reset_after_lockout(), lockout_until=until)
