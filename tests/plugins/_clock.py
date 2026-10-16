"""Test helper: "today" as the product counts it.

Blackbox dates every statement, confirmation and expiry in UTC
(``community.statements.curator_view.today_utc``). A test that builds its expected
day from the machine's local clock (``date.today()``) disagrees with the product
whenever the local date and the UTC date differ — every evening in the Americas,
every morning in Asia — and fails for that reason alone.

Usage::

    from _clock import utc_today
    TODAY = utc_today().isoformat()
    later = (utc_today() + timedelta(days=60)).isoformat()
"""

from __future__ import annotations

from datetime import date

from plugins.blackbox.community.statements.curator_view import today_utc


def utc_today() -> date:
    """The product's day (UTC) as a ``date``."""
    return date.fromisoformat(today_utc())
