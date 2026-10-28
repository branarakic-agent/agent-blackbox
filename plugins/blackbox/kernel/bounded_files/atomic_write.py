"""Write a small file so a reader never sees a torn one — the one implementation.

``os.replace`` is atomic on the same filesystem: the text goes to a sibling temp
file (unique per process and call) and is renamed over *path*, so a concurrent
reader — another agent process, the dashboard — sees either the old or the new
complete file, never a half-written one. 31 files carried their own copy of this
(three spellings, one with 0600) before 2026-10-22; now they share this one.

Usage::

    atomic_write(path, json.dumps(state))              # a plain file
    atomic_write(path, text, mode=0o600)               # a secret: created 0600, never world-readable
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Optional


def atomic_write(path: Path, text: str, *, mode: Optional[int] = None) -> None:
    """Write *text* (UTF-8) to *path* via temp file + rename; parent folders are
    created. With *mode* the file is created with those permission bits from the
    start (``O_EXCL``, so a leftover temp file is never reused)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
    if mode is None:
        tmp.write_text(text, encoding="utf-8")
    else:
        descriptor = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
    os.replace(tmp, path)
