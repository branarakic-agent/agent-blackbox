"""One shared "last probe" time across every Blackbox process on this machine.

A probe that is paced per process (the community pulse: one aggregate query over
the graph's shared memory every ``community_poll_interval`` seconds) multiplies
with the number of protected agents — ten Hermes profiles meant ten whole-tier
counts every 20 s. :class:`ProbeStamp` keeps the time of the last claimed probe
in a tiny file in the Blackbox home, so whichever process is due first takes the
slot and the others wait out the same interval.

The file holds the claimed time as text (not its mtime), so a caller's injected
clock and the stamp agree. Two processes that read the stamp in the same instant
can both claim it — rare, and the cost is one extra probe, never a missed one.
A stamp that cannot be read or written never blocks a probe (fail-open).

Usage::

    STAMP = ProbeStamp(lambda: constants.blackbox_home() / "community-pulse.stamp")
    held_at = STAMP.claim(interval_s, now)   # None = claimed; else another process's claim time
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Optional

from .atomic_write import atomic_write

logger = logging.getLogger(__name__)


class ProbeStamp:
    """The shared record; *path* is a Path or a callable (resolved per claim, so a
    home that moves between calls — tests — is followed)."""

    def __init__(self, path: Path | Callable[[], Path]) -> None:
        self._path = path

    def _file(self) -> Path:
        return self._path() if callable(self._path) else self._path

    def last(self) -> float:
        """The last claimed time, 0.0 when none was recorded or the file is unreadable."""
        try:
            return float(self._file().read_text(encoding="utf-8-sig").strip() or 0.0)
        except (OSError, ValueError):
            return 0.0

    def claim(self, interval_s: float, now: float) -> Optional[float]:
        """Take the probe slot when *interval_s* has passed since the last claim.

        Returns None when claimed (the stamp now reads *now*), else the time of the
        claim that still holds — the caller waits until that plus *interval_s*."""
        last = self.last()
        if 0.0 <= now - last < interval_s:
            return last
        try:
            atomic_write(self._file(), f"{now:.3f}\n")
        except OSError as exc:
            logger.debug("blackbox: probe stamp not written: %s", exc)
        return None

    def clear(self) -> None:
        """Forget the last claim (a reset: the next due probe anywhere takes the slot)."""
        try:
            self._file().unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            logger.debug("blackbox: probe stamp not cleared: %s", exc)
