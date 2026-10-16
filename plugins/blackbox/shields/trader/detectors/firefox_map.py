"""Which Firefox add-on owns an extension storage folder — read from Firefox's own map (Trader Shield).

Firefox keeps each add-on's ``storage.local`` in a folder named by a random,
per-install UUID: ``<profile>/storage/default/moz-extension+++<uuid>^userContextId=4294967295``
(``ExtensionStorageIDB.sys.mjs``). The folder name alone cannot say whether it is
MetaMask's. The profile's ``prefs.js`` holds the map from add-on id to that UUID, in
the preference ``extensions.webextensions.uuids`` (``Extension.sys.mjs``), e.g.
``{"webextension@metamask.io": "ef23dd6a-…", …}`` — verified on real Firefox 157
installs (Mozilla package and Ubuntu snap), 2026-10-13.

Three answers, never a guess (LES-011): the add-on id; or ``None`` when this cannot
tell (no ``prefs.js``, unreadable, malformed, or the folder is not in the map) — the
caller then protects the folder rather than risk leaving a wallet open. Only the
settings file is read; nothing inside any extension's storage is ever opened.

Moved here from ``detection/firefox_extensions.py`` (since deleted).

Usage::

    addon_for("/home/u/.mozilla/firefox/ab12.default", "ef23dd6a-2006-436e-a3a0-6a52d309351c")
    # -> "webextension@metamask.io"
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from collections import OrderedDict
from typing import Optional

from ....kernel.bounded_files import read_small_text

logger = logging.getLogger(__name__)

#: prefs.js is a few KB to a few hundred KB; anything far larger is not a real one.
_MAX_PREFS_BYTES = 8 * 1024 * 1024
#: Profiles whose map is kept; a machine has a handful, so 64 is generous.
_MAX_PROFILES = 64
_UUIDS_PREF = re.compile(r'user_pref\("extensions\.webextensions\.uuids",\s*"((?:[^"\\]|\\.)*)"\);')


def _read_map(prefs_path: str) -> Optional[dict[str, str]]:
    """``{uuid: add-on id}`` from one prefs.js, or None when it cannot be read."""
    # The profile folder comes from a path in the agent's own call, so a symlinked prefs.js is refused.
    text = read_small_text(prefs_path, _MAX_PREFS_BYTES, nofollow=True)
    match = _UUIDS_PREF.search(text) if text is not None else None
    if not match:
        return None
    try:
        mapping = json.loads(json.loads('"' + match.group(1) + '"'))   # a JSON object stored as a JS string
    except ValueError as exc:
        logger.debug("blackbox: Firefox extension map unreadable at %s: %s", prefs_path, exc)
        return None
    if not isinstance(mapping, dict):
        return None
    return {str(uuid).lower(): str(addon) for addon, uuid in mapping.items()}


class _PrefsMaps:
    """Each profile's map, re-read only when its prefs.js changes. One lock.

    Least-recently-used, at most :data:`_MAX_PROFILES` profiles: the keys come from
    folder names in the agent's own calls, so the cache must not grow with them."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: OrderedDict[str, tuple[float, Optional[dict[str, str]]]] = OrderedDict()

    def get(self, profile_dir: str) -> Optional[dict[str, str]]:
        prefs_path = os.path.join(profile_dir, "prefs.js")
        try:
            mtime = os.path.getmtime(prefs_path)
        except OSError:
            return None
        with self._lock:
            cached = self._cache.get(prefs_path)
            if cached and cached[0] == mtime:
                self._cache.move_to_end(prefs_path)
                return cached[1]
        mapping = _read_map(prefs_path)
        with self._lock:
            self._cache[prefs_path] = (mtime, mapping)
            self._cache.move_to_end(prefs_path)
            while len(self._cache) > _MAX_PROFILES:
                self._cache.popitem(last=False)
        return mapping

    def reset(self) -> None:
        with self._lock:
            self._cache.clear()


PREFS_MAPS = _PrefsMaps()


def addon_for(profile_dir: str, uuid: str) -> Optional[str]:
    """The add-on id whose storage folder is ``moz-extension+++<uuid>`` in *profile_dir*,
    or None when Firefox's map cannot tell (see the module doc)."""
    mapping = PREFS_MAPS.get(profile_dir)
    return mapping.get(uuid.lower()) if mapping else None
