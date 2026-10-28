"""YAML config files (Hermes ``config.yaml`` and friends), read and written safely.

:func:`load_yaml` never raises (unreadable -> ``{}``); :func:`dump_yaml` writes
through :func:`atomic_write` (temp file + rename) so a concurrent reader never
sees a torn file. ``yaml`` is None only if PyYAML is somehow absent.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict
from .bounded_files import atomic_write   # the kernel's one torn-free write (re-exported for yaml callers)

logger = logging.getLogger(__name__)

# Hermes 0.21.7 removed PyYAML and reads YAML through its own ruamel-backed ``hermes_yaml``
# (same safe_load / safe_dump calls); older Hermes ships PyYAML. Without either, every config
# read would come back empty and Blackbox would silently run on defaults — so say so loudly.
try:
    import hermes_yaml as yaml  # type: ignore[import-not-found]
except ImportError:
    try:
        import yaml  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - no YAML library at all
        yaml = None  # type: ignore[assignment]
        logger.warning("blackbox: no YAML library (hermes_yaml or PyYAML) — config.yaml cannot be read; "
                       "Blackbox is running on its defaults")


# ---------------------------------------------------------------------------
# YAML helpers (idempotent, preserve unrelated keys)
# ---------------------------------------------------------------------------


def load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None or not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        logger.debug("blackbox.attach: could not parse %s (%s)", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def dump_yaml(path: Path, data: dict[str, Any]) -> None:
    atomic_write(path, yaml.safe_dump(data, default_flow_style=False, sort_keys=False))
