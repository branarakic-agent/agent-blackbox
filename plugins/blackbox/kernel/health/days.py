"""Day arithmetic every age and silence rule shares.

Six modules carried their own ``_days_between`` (four byte-identical) and three
their own ``_today`` before 2026-10-22. Days are ISO ``YYYY-MM-DD`` strings — the
form every curator statement, heartbeat and ledger row records.
"""

from __future__ import annotations

from datetime import UTC, date, datetime


def days_between(earlier: str, later: str) -> int:
    """Whole days from *earlier* to *later* (negative when *later* is first);
    0 when either is not an ISO day — an unreadable date is never an alarm."""
    try:
        return (date.fromisoformat(later) - date.fromisoformat(earlier)).days
    except (TypeError, ValueError):
        return 0


def today_utc() -> str:
    """Today's UTC day as ``YYYY-MM-DD`` — the one clock the day rules read."""
    return datetime.now(UTC).date().isoformat()
