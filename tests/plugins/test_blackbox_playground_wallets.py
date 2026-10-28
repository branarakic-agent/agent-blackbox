"""Wallet tests in the Playground (2026-10-27): every wallet Trader Shield finds on the machine,
plus a generated seed phrase and key, run through the REAL pre-tool hook inside the sandbox.

A real store for every supported wallet pack is laid out in a temporary HOME (the attack-table
tests' own layout), so these prove each self-test reaches the outcome it promises — and that a
test stays in the sandbox, never prints its generated secret, and says why it is let through
when the shield is off or the wallet is not ticked.
"""

from __future__ import annotations

import dataclasses
import secrets

import pytest

from test_blackbox_trader_shield_attacks import _materialise, _solana_key, _supported
from plugins.blackbox import playground, shields
from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.dashboard import playground_routes
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.kernel import constants, crypto_secrets
from plugins.blackbox.kernel.crypto_secrets import seed_phrase
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.trader import detectors, mode as trader_mode, self_tests

PACKS = [pack.id for pack in _supported("trader")]


def _cfg(**overrides):
    return dataclasses.replace(config_mod.BlackboxConfig(mode="block", report=False, community_sandbox=True),
                               **overrides)


@pytest.fixture
def machine(tmp_path, monkeypatch):
    """A HOME holding one store per supported wallet, Blackbox's home under it, the real hook
    in block mode with local rules only; answers a function that sets Trader Shield's mode."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / ".config"))
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path / "bb")
    key_file = "[" + ",".join(str(b) for b in _solana_key()) + "]"
    for pack in _supported("trader"):
        _materialise(pack, tmp_path, key_file)
    monkeypatch.setattr(hooks, "_config", lambda: _cfg())
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    detectors.EXISTING_STORES.reset()

    def set_mode(enabled=True, wallets=tuple(PACKS)):
        active = trader_mode.build(enabled=enabled, wallets=wallets)
        monkeypatch.setattr(trader_mode, "current", lambda: active)

    set_mode()
    yield tmp_path
    detectors.EXISTING_STORES.reset()


def test_every_supported_wallet_found_here_gets_a_key_store_test(machine):
    groups = {test["group"] for test in playground.wallet_tests() if test["id"].startswith("vault:")}
    assert groups == set(PACKS)


def test_every_wallet_test_has_the_outcome_it_promises_in_block_mode(machine):
    results = {test["id"]: playground.run_wallet_test(test["id"], _cfg()) for test in playground.wallet_tests()}
    assert {test_id: (result.decision, result.expect) for test_id, result in results.items()
            if result.decision != result.expect} == {}
    assert all(result.note == "" for result in results.values())


def test_with_the_shield_off_every_wallet_test_is_let_through_and_says_why(machine, monkeypatch):
    active = trader_mode.build(enabled=False, wallets=tuple(PACKS))
    monkeypatch.setattr(trader_mode, "current", lambda: active)
    results = [playground.run_wallet_test(test["id"], _cfg()) for test in playground.wallet_tests()
               if test["id"].startswith("vault:")]
    assert results and {result.decision for result in results} == {"allowed"}
    assert all("Trader Shield is off" in result.note for result in results)


def test_an_unticked_wallet_is_let_through_and_named(machine, monkeypatch):
    active = trader_mode.build(enabled=True, wallets=tuple(p for p in PACKS if p != "metamask"))
    monkeypatch.setattr(trader_mode, "current", lambda: active)
    vault = next(test for test in playground.wallet_tests() if test["id"].startswith("vault:metamask:"))
    result = playground.run_wallet_test(vault["id"], _cfg())
    assert result.decision == "allowed" and result.note == "MetaMask is not ticked under Wallets to protect."


def test_a_run_stays_in_the_sandbox_and_never_writes_the_generated_secret(machine, monkeypatch):
    phrase = self_tests.generated_seed_phrase()
    monkeypatch.setattr(self_tests, "generated_seed_phrase", lambda: phrase)
    listed = playground.wallet_tests()
    result = playground.run_wallet_test("seed:sent-in-url", _cfg())
    assert result.decision == "blocked" and "secret:seed-phrase" in result.identifiers
    home = machine / "bb"
    assert (home / "sandbox" / "findings.jsonl").exists() and not (home / "findings.jsonl").exists()
    written = "".join(path.read_text(encoding="utf-8") for path in home.rglob("*") if path.is_file())
    for word_run in (phrase, phrase.replace(" ", "+")):
        assert word_run not in written and word_run not in str(listed) and word_run not in str(result.to_dict())


def test_the_generated_phrase_is_a_valid_seed_phrase():
    assert seed_phrase.find_seed_phrase_runs(f"seed words: {self_tests.generated_seed_phrase()}")


def test_phrase_from_entropy_matches_the_bip39_reference_vectors():
    # Trezor's published BIP-39 English vectors (all-zero and all-0x7f entropy).
    assert crypto_secrets.phrase_from_entropy(bytes(16)) == " ".join(["abandon"] * 11 + ["about"])
    assert crypto_secrets.phrase_from_entropy(b"\x7f" * 16) == (
        "legal winner thank year wave sausage worth useful legal winner thank yellow")
    assert len(crypto_secrets.phrase_from_entropy(secrets.token_bytes(32)).split()) == 24
    assert crypto_secrets.phrase_from_entropy(bytes(15)) is None


def test_a_wallet_test_needs_sandbox_mode_only():
    with pytest.raises(playground.PlaygroundRefused, match="Sandbox mode is off"):
        playground.run_wallet_test("seed:sent-in-url", _cfg(community_sandbox=False))


def test_an_unknown_test_id_is_refused(machine):
    with pytest.raises(playground.PlaygroundRefused, match="not available on this machine"):
        playground.run_wallet_test("vault:nothing:" + secrets.token_hex(5), _cfg())


def test_a_failing_builder_lists_nothing_and_never_raises(monkeypatch):
    def broken(_mode):
        raise RuntimeError("boom")

    monkeypatch.setattr(shields.SELF_TESTS, "builder", lambda shield_id: broken)
    assert shields.self_tests() == []


def test_the_routes_list_the_tests_and_answer_409_with_the_reason(monkeypatch):
    monkeypatch.setattr(config_mod, "load_blackbox_config", lambda: _cfg())
    monkeypatch.setattr(playground, "wallet_tests", lambda: [{"id": "seed:sent-in-url"}])
    assert playground_routes.wallet_list_payload() == {"tests": [{"id": "seed:sent-in-url"}]}

    def refuse(test_id):
        raise playground.PlaygroundRefused("Sandbox mode is off.")

    monkeypatch.setattr(playground, "run_wallet_test", refuse)
    assert playground_routes.wallet_run_payload({"id": "x"}) == (409, {"ok": False, "error": "Sandbox mode is off."})


def test_a_run_shows_in_the_sandbox_feed_the_dashboard_merges_into_agent_activity(machine, monkeypatch):
    """Amos (2026-10-27): sandbox tests show in Local and Agent activity and alert like real
    findings — the feed carries this run as a finding row AND as activity entries."""
    monkeypatch.setattr(config_mod, "load_blackbox_config", lambda: _cfg())
    playground.run_wallet_test("seed:sent-in-url", _cfg())
    feed = playground_routes.local_payload()
    assert feed["sandbox"] is True
    assert any(row.get("identifier") == "secret:seed-phrase" for row in feed["findings"])
    assert any(entry.get("event") in ("blocked", "flagged") for entry in feed["audit"])
    assert feed["local"]["threatCount"] >= 1


def test_outside_sandbox_mode_the_feed_is_empty(monkeypatch):
    monkeypatch.setattr(config_mod, "load_blackbox_config", lambda: _cfg(community_sandbox=False))
    assert playground_routes.local_payload()["audit"] == []


def test_in_sandbox_mode_recent_events_include_the_tests_tagged(machine, monkeypatch):
    """Amos (2026-10-27): a wallet test shows in the shield's Recent events while in sandbox mode."""
    from plugins.blackbox.dashboard import shields_routes

    monkeypatch.setattr(config_mod, "load_blackbox_config", lambda: _cfg())
    monkeypatch.setattr(shields_routes, "load_blackbox_config", lambda: _cfg())
    playground.run_wallet_test(next(t["id"] for t in playground.wallet_tests() if t["id"].startswith("vault:")), _cfg())
    events = shields_routes.events_payload("trader")
    assert events and all(event.get("sandbox") is True for event in events)
    monkeypatch.setattr(shields_routes, "load_blackbox_config", lambda: _cfg(community_sandbox=False))
    assert shields_routes.events_payload("trader") == []
