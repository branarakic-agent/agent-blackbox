"""Verified-graph progress and download totals for status, health and the meter.

Progress (``progress.json``): how many confirmed assets the last refresh covered
and when the node's asset count last grew — :func:`catching_up` drives the faster
refresh pace while the graph is still arriving. :func:`verified_download_totals`
is the one aggregate query behind the dashboard's sync meter.

The per-asset reader and its on-disk row cache that lived here (KI-288) were
replaced by the live lookups (DKG-lookup B6): the small tiers are read by typed
lanes in :mod:`..fetching`, dependency / IOC rules stay in the node's store.
:func:`forget_cached_assets` removes the old cache files.

Usage: ``record_progress(cg_id, PartitionRead(total=n, compiled=n))`` · ``progress(cg_id)``
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ...kernel import constants
from ...kernel.dkg_client import DkgClient, extract_binding
from .. import graph_queries
from .rows import Row
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

#: The node is treated as still receiving the graph until its asset count has
#: not grown for this long. A recovering DKG node lists only what it already
#: holds, so "every listed asset compiled" says nothing about the assets still
#: on their way; and downloads pause for minutes between batches (bench
#: blackbox-native-a, 2026-10-06: 5 assets listed and compiled while 559 more
#: were queued, so the rules waited an hour behind a node holding 288).
GROWTH_QUIET_SECONDS = 900.0


@dataclass
class PartitionRead:
    """What one refresh read: the rows of every partition available, and progress."""

    rows: list[Row] = field(default_factory=list)
    total: int = 0          # confirmed partitions the node lists
    compiled: int = 0       # of those, how many have rows (cached or read now)
    read_now: int = 0       # read from the node in this refresh
    stopped_early: str = "" # why reading new partitions stopped, if it did


def forget_cached_assets() -> int:
    """Delete the per-asset row cache the live lookups replaced (DKG-lookup B6):
    564 gzip files that nothing reads any more. Returns how many were removed."""
    root = constants.blackbox_home() / "verified_partitions"
    removed = 0
    for path in root.glob("*.json.gz") if root.is_dir() else []:
        try:
            path.unlink()
            removed += 1
        except OSError:
            continue
    return removed


def _progress_path() -> Path:
    return constants.blackbox_home() / "verified_partitions" / "progress.json"


def record_progress(cg_id: str, read: PartitionRead) -> None:
    """Remember how much of the verified graph the last refresh compiled (KI-290).

    ``blackbox status`` shows it, so rules that cover only part of what the node
    holds are visible instead of looking complete. It also keeps when the
    node's asset count last grew, which :func:`catching_up` reads. Best effort:
    a failed write only loses the status line and the faster refresh pace.
    """
    path = _progress_path()
    now = time.time()
    record = {
        "context_graph_id": cg_id, "assets_total": read.total, "assets_compiled": read.compiled,
        "assets_read_now": read.read_now, "stopped_early": read.stopped_early, "at": now,
        "total_grew_at": _total_grew_at(progress(cg_id), read.total, now),
    }
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps(record))
    except OSError as exc:
        logger.warning("blackbox: could not record verified-graph progress: %s", exc)


def _total_grew_at(previous: Optional[dict[str, object]], total: int, now: float) -> float:
    """When the asset count last grew: *now* if it grew since *previous* (or
    this is the first record of a non-empty graph), else the earlier time."""
    before_total = (previous or {}).get("assets_total")
    before_grew_at = (previous or {}).get("total_grew_at")
    if isinstance(before_total, int) and total <= before_total and isinstance(before_grew_at, (int, float)):
        return float(before_grew_at)
    return now if total > 0 else 0.0


def progress(cg_id: str) -> Optional[dict[str, object]]:
    """The last recorded compile progress for *cg_id*, or None."""
    try:
        record = json.loads(_progress_path().read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return None
    return record if isinstance(record, dict) and record.get("context_graph_id") == cg_id else None


def catching_up(cg_id: str) -> bool:
    """True while *cg_id*'s verified rules are behind the node or the node is
    still receiving the graph: the last refresh compiled only part of what the
    node listed (assets deferred by a store deadline or the read budget), or
    the node's asset count grew within :data:`GROWTH_QUIET_SECONDS`. False when
    nothing was recorded: a graph never read partition by partition is not
    catching up."""
    done = progress(cg_id) or {}
    compiled, total = done.get("assets_compiled"), done.get("assets_total")
    if isinstance(compiled, int) and isinstance(total, int) and compiled < total:
        return True
    grew_at = done.get("total_grew_at")
    return isinstance(grew_at, (int, float)) and grew_at > 0 and time.time() - grew_at < GROWTH_QUIET_SECONDS


@dataclass(frozen=True)
class DownloadTotals:
    """Verified assets this node holds confirmed, and their public triples."""

    assets: int
    triples: int


def verified_download_totals(client: DkgClient, cg_id: str, *,
                             timeout: Optional[float] = None) -> Optional[DownloadTotals]:
    """How much of the verified graph the node has downloaded and confirmed —
    one aggregate query on its _meta; None when the node cannot say (a failed
    read is "could not tell", never zero — LES-011)."""
    query = graph_queries._verified_partition_totals_sparql(cg_id)
    if not query:
        return None
    rows = client.query(query, cg_id, view=None, on_error=None, timeout=timeout)
    if not rows:
        return None
    try:
        return DownloadTotals(assets=int(extract_binding(rows[0].get("assets")) or 0),
                              triples=int(float(extract_binding(rows[0].get("triples")) or 0)))
    except (TypeError, ValueError):
        return None
