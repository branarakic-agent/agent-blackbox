"""How much the beat may ask outside sources: the per-beat budget and each source's token bucket (§03.3, F-029).

Without a budget the beat asked OSV once per open queue item on every beat;
a queue of thousands tripped the rate limit and every answer became "could
not tell" — nothing confirmed. So:

* :class:`LookupBudget` (frozen) — at most 100 items per beat, lane order,
  oldest first; a deferred or not-proven item is only due on its re-test days
  (7 and 21 after it entered that state).
* :class:`TokenBucket` — one per source, its own lock, sized from the
  source's published limit.
* :func:`queue_metrics` — queue depth and oldest item age for the console and
  Slack metrics (F-035).

Usage::

    picked = select_for_lookup(items, LookupBudget(), today="2026-10-11")
    metrics = queue_metrics(items, today="2026-10-11")
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence

from ..queue import Lane
from ...kernel.health import days_between

#: Item states (§03.3 verdicts). An ``open`` item is due every beat; the
#: others only on their re-test days.
OPEN = "open"
DEFERRED = "deferred"
NOT_PROVEN = "not-proven"
ITEM_STATES = frozenset({OPEN, DEFERRED, NOT_PROVEN})

ITEMS_PER_BEAT = 100
RETEST_DAYS = (7, 21)


@dataclass(frozen=True)
class LookupItem:
    """One queue item as the look-up step sees it: its ``identifier`` and
    ``lane``, the ISO day it was ``first_seen`` (its age), its ``state``
    (one of :data:`ITEM_STATES`) and, for deferred / not-proven items, the ISO
    day it entered that state (``state_since``)."""

    identifier: str
    lane: Lane
    first_seen: str
    state: str = OPEN
    state_since: str = ""

    def __post_init__(self) -> None:
        if self.state not in ITEM_STATES:
            raise ValueError(f"unknown item state {self.state!r}")
        if self.state != OPEN and not self.state_since:
            raise ValueError(f"a {self.state} item needs the day it entered that state")


@dataclass(frozen=True)
class LookupBudget:
    """What one beat may look up: ``items_per_beat`` items, and the
    ``retest_days`` on which a deferred / not-proven item is due."""

    items_per_beat: int = ITEMS_PER_BEAT
    retest_days: tuple[int, ...] = RETEST_DAYS

    def due(self, item: LookupItem, today: str) -> bool:
        """An open item is always due; a deferred / not-proven one only on a re-test day."""
        if item.state == OPEN:
            return True
        return days_between(item.state_since, today) in self.retest_days


def select_for_lookup(items: Sequence[LookupItem], budget: LookupBudget, today: str) -> tuple[LookupItem, ...]:
    """The items this beat looks up: the due ones, lane order then oldest
    first (identifier breaks ties so the pick is deterministic), cut at the budget."""
    due = sorted((item for item in items if budget.due(item, today)),
                 key=lambda item: (item.lane.value, item.first_seen, item.identifier))
    return tuple(due[:budget.items_per_beat])


@dataclass(frozen=True)
class QueueMetrics:
    """``depth`` — open queue items; ``oldest_age_days`` — age of the oldest (0 when empty)."""

    depth: int
    oldest_age_days: int


def queue_metrics(items: Sequence[LookupItem], today: str) -> QueueMetrics:
    """Queue depth and the oldest item's age in whole days, for the console / Slack metrics (F-035)."""
    if not items:
        return QueueMetrics(depth=0, oldest_age_days=0)
    oldest = min(item.first_seen for item in items)
    return QueueMetrics(depth=len(items), oldest_age_days=max(0, days_between(oldest, today)))



class TokenBucket:
    """A rate limiter for one source: ``capacity`` requests, refilled evenly
    over ``period_seconds`` (the source's published limit). :meth:`take`
    returns False when drained — the caller answers UNAVAILABLE, never waits.
    Its own lock, so concurrent beats never overspend one source."""

    def __init__(self, capacity: int, period_seconds: float, *, clock: Optional[Callable[[], float]] = None) -> None:
        if capacity < 1 or period_seconds <= 0:
            raise ValueError("a bucket needs at least one token per positive period")
        self._capacity = float(capacity)
        self._refill_per_second = capacity / period_seconds
        self._clock = clock or time.monotonic
        self._tokens = self._capacity
        self._last = self._clock()
        self._lock = threading.Lock()

    def take(self) -> bool:
        """Spend one token if one is left."""
        with self._lock:
            now = self._clock()
            self._tokens = min(self._capacity, self._tokens + (now - self._last) * self._refill_per_second)
            self._last = now
            if self._tokens < 1:
                return False
            self._tokens -= 1
            return True
