"""The service's own daily limit on what it signs (Community Curation C9, plan §07).

Every reader already caps what the community curators can raise per day. The
service caps ITSELF lower (``policy.SERVICE_CONFIRMATIONS_PER_DAY``,
``policy.SERVICE_LISTINGS_PER_DAY``), so a service gone wrong — a poisoned
advisory source, a bug — is slowed at its own machine first. Only statements
that RAISE enforcement are counted; reductions are never limited.

State: ``$BLACKBOX_HOME/curate/service_budget.json`` — today's counts. One
class owns the file, one lock, atomic writes.

Usage::

    budget = ServiceBudget()
    if budget.left("confirm", today): ...sign...; budget.spend("confirm", today)
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Optional

from .. import keys
from . import policy
from ...kernel.bounded_files import atomic_write

_FILE = "service_budget.json"


def _limits() -> dict[str, int]:
    return {"confirm": policy.SERVICE_CONFIRMATIONS_PER_DAY, "list": policy.SERVICE_LISTINGS_PER_DAY}


class ServiceBudget:
    """How many raising statements the service signed today, by kind (``confirm`` | ``list``)."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _FILE)

    def _counts(self, today: str) -> dict[str, int]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            if data.get("day") == today:
                return {kind: int(data.get(kind, 0)) for kind in _limits()}
        except (OSError, ValueError, TypeError, AttributeError):
            pass
        return {kind: 0 for kind in _limits()}

    def left(self, kind: str, today: str) -> int:
        """How many more statements of *kind* the service may sign today."""
        return max(0, _limits()[kind] - self._counts(today)[kind])

    def spend(self, kind: str, today: str) -> None:
        """Record one signed statement of *kind* for *today*."""
        with self._lock:
            counts = self._counts(today)
            counts[kind] += 1
            self._path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self._path, json.dumps({"day": today, **counts}))
