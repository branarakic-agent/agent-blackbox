"""Trader Shield's ``browser-extension`` kind: a browser wallet's key store, found in a path.

A browser wallet keeps its encrypted vault (the seed and keys, locked by the user's
password) in the browser profile. Copied off the machine, the vault can be attacked
offline with password crackers, so reading it is the first step of every wallet
stealer reviewed on 2026-10-12 (research report "Local crypto protection rules",
misc/research). No agent task needs those files.

What is matched, built from each supported pack's ``stores`` (``wallets/<id>/wallet.json``):

* its Chromium extension ids, in all three places a Chromium browser keeps an
  extension's data, in any profile under any browser folder (Chromium
  ``extensions/common/constants.h``): ``Local Extension Settings/<id>``,
  ``Sync Extension Settings/<id>`` and
  ``IndexedDB/chrome-extension_<id>_0.indexeddb.leveldb|blob`` — MetaMask writes a
  backup copy of its vault there (``metamask-backup``, metamask-extension
  ``shared/lib/stores/persistence-manager.ts``);
* Firefox extension storage, ``storage/default/moz-extension+++<uuid>^userContextId=4294967295``
  (``ExtensionStorageIDB.sys.mjs``), placed by the profile's own map (:mod:`.firefox_map`):
  a pack's ``stores.firefox`` add-on id names its pack, another add-on is not a wallet,
  and a folder the map cannot place is :data:`UNPLACED` — a pack-less match the shield
  protects as a whole rather than leave open (LES-011).

Where the stores are laid out under one browser folder (for the archive check) depends
on the folder's ``engine`` in ``browsers.json``: :meth:`BrowserExtensionMatcher.store_globs`.

Moved here from ``detection/wallet_files.py`` (since deleted), built from packs instead of
its ``WALLETS`` rows.

Pattern: Specification — a pack is data (ids); one matcher serves every pack added later.

Usage::

    matcher = BrowserExtensionMatcher(mode.wallet_packs())
    matcher.owner("~/.config/google-chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log")
    # -> Owner(pack="metamask", wallet="MetaMask")
"""

from __future__ import annotations

import os
import re
from typing import Any, Iterable, NamedTuple, Optional

from ...contract import Pack
from . import firefox_map

KIND = "browser-extension"
#: Shown for Firefox extension storage the profile's map cannot tie to one pack.
FIREFOX_EXTENSION = "a Firefox extension"
_FIREFOX_STORAGE = r"storage/default/moz-extension\+\+\+[^/]*\^usercontextid=4294967295"
_FIREFOX_PATTERN = re.compile(rf"(?:^|/){_FIREFOX_STORAGE}(?:/|$)")
#: The same folder on the path as written (case kept, so the profile's prefs.js can be found).
_FIREFOX_FOLDER = re.compile(r"(?i)^(?P<profile>.*?)/storage/default/moz-extension\+\+\+(?P<uuid>[0-9a-f-]{36})"
                             r"\^usercontextid=4294967295(?:/|$)")


class Owner(NamedTuple):
    """Whose key store a path lies in: the pack id (``""`` when no pack can be named) and
    the name a person reads."""

    pack: str
    wallet: str


#: A Firefox storage folder the map cannot place: protected for the shield as a whole.
UNPLACED = Owner("", FIREFOX_EXTENSION)


def _expanded(path: str) -> str:
    """*path* with ``~``, ``$HOME`` and Windows ``%VARS%`` expanded, ``\\`` made ``/``
    and ``.``/``..`` resolved — case kept."""
    text = str(path or "").strip()
    text = re.sub(r"%([A-Za-z_]+)%", lambda m: os.environ.get(m.group(1), m.group(0)), text)
    text = os.path.expanduser(os.path.expandvars(text)).replace("\\", "/")
    return os.path.normpath(text).replace("\\", "/") if text else ""


def normalize_path(path: str) -> str:
    """:func:`_expanded`, lower-cased (macOS and Windows file names ignore case), so one
    pattern serves every OS."""
    return _expanded(path).lower()


def _store_pattern(chromium_ids: Iterable[str]) -> re.Pattern[str]:
    ids = "|".join(re.escape(store_id) for store_id in chromium_ids)
    return re.compile(
        rf"(?:^|/)(?:(?:local|sync) extension settings/(?:{ids})"
        rf"|indexeddb/chrome-extension_(?:{ids})_0\.indexeddb\.(?:leveldb|blob))(?:/|$)"
    )


def _stores(pack: Pack) -> dict[str, Any]:
    stores = pack.data.get("stores")
    return stores if isinstance(stores, dict) else {}


class BrowserExtensionMatcher:
    """Every supported ``browser-extension`` pack in *packs*, compiled once into the
    path patterns and the Firefox add-on map (other kinds and statuses are skipped)."""

    def __init__(self, packs: Iterable[Pack]) -> None:
        self.packs = tuple(pack for pack in packs if pack.status == "supported" and pack.kind == KIND)
        # A pack with no Chromium id gets no pattern: an empty alternation would match every path.
        self._patterns = tuple((Owner(pack.id, pack.name), _store_pattern(_stores(pack)["chromium"]))
                               for pack in self.packs if _stores(pack).get("chromium"))
        self._firefox = {addon: Owner(pack.id, pack.name)
                         for pack in self.packs for addon in _stores(pack).get("firefox", [])}

    def owner(self, path: str) -> Optional[Owner]:
        """Whose key store *path* lies inside, or ``None``."""
        normalized = normalize_path(path)
        if not normalized:
            return None
        for owner, pattern in self._patterns:
            if pattern.search(normalized):
                return owner
        if _FIREFOX_PATTERN.search(normalized):
            return self._firefox_owner(path)
        return None

    def _firefox_owner(self, path: str) -> Optional[Owner]:
        """The pack a Firefox extension-storage *path* belongs to, by Firefox's own map;
        None when the map names an add-on that is not a wallet; :data:`UNPLACED` when the
        map cannot tell."""
        match = _FIREFOX_FOLDER.search(_expanded(path))
        if not match:
            return UNPLACED
        addon = firefox_map.addon_for(match.group("profile"), match.group("uuid"))
        if addon is None:
            return UNPLACED
        return self._firefox.get(addon)

    def store_globs(self, root: str, engine: str) -> list[str]:
        """The exact key-store folder globs under one browser folder of *engine* — never a
        deep walk (a profile holds thousands of cache files)."""
        if engine == "firefox":
            return [os.path.join(root, "storage", "default", "moz-extension+++*")]
        out = []
        for pack in self.packs:
            for store_id in _stores(pack).get("chromium", []):
                for profile in (os.path.join(root, "*"), root):              # Opera keeps no profile folder
                    out.append(os.path.join(profile, "Local Extension Settings", store_id))
                    out.append(os.path.join(profile, "Sync Extension Settings", store_id))
                    out.append(os.path.join(profile, "IndexedDB", f"chrome-extension_{store_id}_0.indexeddb.*"))
        return out
