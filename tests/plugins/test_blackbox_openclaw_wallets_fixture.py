"""The OpenClaw bridge's wallet fixture equals what the shields' packs and roots say today.

``integrations/openclaw/src/generated/wallets.json`` is written by
``scripts/gen_openclaw_wallets.py``. This test regenerates it in memory and compares
bytes, so a pack or browser-root change without a regenerated fixture is a red suite.
SDK-free: no Node and no OpenClaw package, just the Python registry.
"""

import importlib.util
import json
from pathlib import Path

import pytest
from _blackbox_loader import load_blackbox

shields = load_blackbox("shields")   # mounts the plugin, so the script reuses this same copy
packs_loader = load_blackbox("shields.packs")
contract = load_blackbox("shields.contract")

REPO = Path(__file__).resolve().parents[2]
FIXTURE = REPO / "integrations" / "openclaw" / "src" / "generated" / "wallets.json"
_spec = importlib.util.spec_from_file_location("gen_openclaw_wallets", REPO / "scripts" / "gen_openclaw_wallets.py")
generator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(generator)

REGENERATE = "stale fixture: run `uv run python scripts/gen_openclaw_wallets.py` and commit the result"


def _trader() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))["shields"]["trader"]


def test_committed_fixture_is_byte_identical_to_a_fresh_generation():
    assert FIXTURE.read_bytes() == generator.render().encode("utf-8"), REGENERATE


def test_fixture_ends_in_exactly_one_newline():
    text = FIXTURE.read_text(encoding="utf-8")
    assert text.endswith("}\n") and not text.endswith("\n\n")


def test_every_registered_shield_is_in_the_fixture():
    in_fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))["shields"]
    assert sorted(in_fixture) == sorted(shield.id for shield in shields.all_shields())


def test_eleven_supported_packs_carry_their_kind_data():
    supported = {pack["id"]: pack for pack in _trader()["packs"] if pack["status"] == "supported"}
    assert list(supported) == ["metamask", "phantom", "exodus", "electrum", "solana-cli",
                               "rabby", "coinbase-wallet", "trust-wallet", "okx-wallet", "keplr", "solflare"]
    for pack_id in ("metamask", "phantom"):
        assert supported[pack_id]["kind"] == "browser-extension"
        assert supported[pack_id]["stores"]["chromium"] and supported[pack_id]["stores"]["firefox"]
    for pack_id in ("exodus", "electrum"):
        assert supported[pack_id]["kind"] == "desktop-app" and supported[pack_id]["places"]
    solana = supported["solana-cli"]
    assert solana["kind"] == "cli-key-file" and solana["places"]
    assert solana["pointer"] == {"config": "$XDG_CONFIG_HOME/solana/cli/config.yml",
                                 "key": "keypair_path", "max_bytes": 65536}


def test_supported_pack_data_equals_the_loaded_manifests():
    loaded = {pack.id: pack for pack in packs_loader.load_packs(shields.get("trader"))}
    for entry in _trader()["packs"]:
        pack = loaded[entry["id"]]
        assert entry == {"id": pack.id, "name": pack.name, "kind": pack.kind, "status": pack.status,
                         "order": pack.order, **pack.data}


def test_no_planned_pack_ids_are_left():
    planned = [pack["id"] for pack in _trader()["packs"] if pack["status"] == "planned"]
    assert planned == []   # the six were promoted to supported on 2026-10-16


def test_all_31_browser_roots_are_listed_in_file_order():
    roots, health = packs_loader.load_browser_roots(shields.get("trader"))
    fixture_roots = _trader()["browser_roots"]
    assert len(fixture_roots) == 31 and health == ()
    assert fixture_roots == [root.as_json() for root in roots]
    assert sum(root["engine"] == "firefox" for root in fixture_roots) == 7


def test_generation_refuses_an_unavailable_pack(monkeypatch):
    broken = packs_loader.ShieldData(packs=(contract.Pack(
        id="metamask", name="metamask", kind="", status="unavailable", order=0, folder=REPO,
        reason="manifest too large"),))
    monkeypatch.setattr(packs_loader, "load_shield_data", lambda shield: broken)
    with pytest.raises(generator.FixtureError, match="metamask: manifest too large"):
        generator.render()


def test_generation_refuses_a_dropped_browser_root(monkeypatch):
    dropped = packs_loader.ShieldData(health=("browser folder rule unavailable — duplicate path",))
    monkeypatch.setattr(packs_loader, "load_shield_data", lambda shield: dropped)
    with pytest.raises(generator.FixtureError, match="duplicate path"):
        generator.render()
