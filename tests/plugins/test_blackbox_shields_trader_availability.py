"""Each browser wallet pack says where its publisher ships it and whether Blackbox guards it there.

``availability`` is documentation data (the dashboard's Docs page reads it; detection never does),
but it is validated like the rest of the pack: a wrong shape makes the pack unavailable, and an
entry may only say "protected" for a store whose ids the pack actually lists — the docs can never
claim a protection the detector does not have. Researched 2026-10-16 from each publisher's own
download page and the stores' own listings.
"""

from __future__ import annotations

import copy

import pytest

from _blackbox_loader import load_blackbox

shields = load_blackbox("shields")
detectors = load_blackbox("shields.trader.detectors")
packs_loader = load_blackbox("shields.packs")

TRADER = shields.get("trader")
PACKS = {pack.id: pack for pack in packs_loader.load_packs(TRADER)}
BROWSER_PACKS = [pack for pack in PACKS.values() if pack.kind == "browser-extension"]
CHECK = next(detector for detector in detectors.DETECTORS if "browser-extension" in detector.KINDS)


def _manifest(pack_id: str) -> dict:
    pack = PACKS[pack_id]
    return copy.deepcopy({"id": pack.id, "name": pack.name, "kind": pack.kind, "status": pack.status,
                          "order": pack.order, "verified": pack.verified, "source": pack.source, **pack.data})


def test_every_browser_wallet_states_its_stores_with_sources():
    for pack in BROWSER_PACKS:
        stores = [entry["store"] for entry in pack.data["availability"]]
        assert stores == ["Chrome Web Store", "Firefox Add-ons", "Edge Add-ons", "Safari"], pack.id
        assert CHECK.validate_pack(_manifest(pack.id)) is None, pack.id
        for entry in pack.data["availability"]:
            if entry["state"] == "protected":
                assert entry.get("url", "").startswith("https://") and entry.get("source"), (pack.id, entry["store"])


def test_the_researched_firefox_and_edge_answers():
    def state(pack_id, store):
        return next(entry["state"] for entry in PACKS[pack_id].data["availability"] if entry["store"] == store)
    assert {p for p in PACKS if p in {pack.id for pack in BROWSER_PACKS} and state(p, "Firefox Add-ons") == "protected"} \
        == {"metamask", "phantom", "keplr", "solflare"}
    assert state("coinbase-wallet", "Firefox Add-ons") == "not-offered"
    assert state("keplr", "Edge Add-ons") == "not-covered"   # Keplr's own Edge build has its own id
    assert state("metamask", "Edge Add-ons") == "protected"
    assert all(state(pack.id, "Safari") == "not-offered" for pack in BROWSER_PACKS)


@pytest.mark.parametrize("change, problem", [
    (lambda m: m["availability"][0].update(state="maybe"), "availability state must be one of"),
    (lambda m: m["availability"][0].update(url="http://example.com"), "https link"),
    (lambda m: m["availability"][0].update(extra=1), "takes store, browsers, state"),
    (lambda m: m["availability"][0].update(browsers=[]), "lists its browsers"),
    (lambda m: m.update(availability=[]), "non-empty list"),
])
def test_a_malformed_entry_is_refused(change, problem):
    manifest = _manifest("phantom")
    change(manifest)
    assert problem in (CHECK.validate_pack(manifest) or "")


def test_a_protected_claim_needs_the_pack_ids_for_that_store():
    manifest = _manifest("coinbase-wallet")   # Chromium ids only
    firefox = next(entry for entry in manifest["availability"] if entry["store"] == "Firefox Add-ons")
    firefox.update(state="protected", url="https://addons.mozilla.org/x", source="test")
    assert "lists no firefox id" in (CHECK.validate_pack(manifest) or "")


def test_a_pack_without_availability_still_loads():
    manifest = _manifest("phantom")
    del manifest["availability"]
    assert CHECK.validate_pack(manifest) is None
