"""The one-graph trial's testnet mode (``--network testnet``): the parts that run without a node.

* A testnet node is relay-only from its first start: it announces a dead address and
  a circuit through each relay of the network file, nothing it could be dialled on.
* Blackbox's node settings go on top of the testnet base; the keys that make the node a
  relay-only node of the testnet stay the trial's.
* The curator's wallets are copied encrypted, never the source node's own agent wallet,
  never a plaintext key.
* Links between the trial's nodes are classified relayed or direct; a direct one is named.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))   # the trial's package sits in scripts/

from blackbox_one_graph_trial import actor_actions, testnet
from blackbox_one_graph_trial.actors import NodeEndpoint
from blackbox_one_graph_trial.report import TrialReport
from blackbox_one_graph_trial.steps import ArrivalWatcher, Trial, TrialState

from plugins.blackbox.kernel.dkg_client import DkgError
from tests.waiting import wait_until

RELAYS = ["/ip4/203.0.113.1/tcp/9090/p2p/12D3KooWRelayOne", "/ip4/203.0.113.2/tcp/9090/p2p/12D3KooWRelayTwo"]


def _testnet(tmp_path: Path, **options) -> testnet.Testnet:
    repo = tmp_path / "dkg"
    (repo / "network").mkdir(parents=True)
    (repo / "network" / "testnet.json").write_text(json.dumps({"relays": RELAYS}), encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return testnet.Testnet(repo, run_dir, testnet.TestnetOptions(homes=tmp_path / "homes", **options))


def test_announce_is_a_dead_address_and_a_circuit_per_relay():
    announce = testnet.relay_only_announce(RELAYS)

    assert announce[0] == testnet.DEAD_ADDRESS
    assert announce[1:] == [f"{relay}/p2p-circuit" for relay in RELAYS]


def test_blackbox_settings_keep_the_testnet_network_keys(tmp_path, monkeypatch):
    nodes = _testnet(tmp_path)
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "config.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "blackbox"))
    settings = actor_actions.node_settings({"staging_home": str(staging), "graph": "0xabc/bb-trial",
                                            "installer": str(REPO / "plugins/blackbox/setup/blackbox-install.sh")})

    nodes._create(2, overrides=settings["config"], wallets=False)
    config = nodes.config(2)

    assert config["networkConfig"] == "testnet" and config["nodeRole"] == "edge"
    assert config["announceAddresses"] == testnet.relay_only_announce(RELAYS)
    assert config["apiPort"] == nodes.api_port(2) and config["listenPort"] == 0
    assert "chain" not in config and "relayPeers" not in config   # the network file's chain and relays
    assert config["autoUpdate"] == {"enabled": False}
    assert config["syncSharedMemoryOnConnect"] is True   # Blackbox's own setting is on top
    assert (nodes.home(2) / "auth.token").stat().st_mode & 0o077 == 0


def _wallet_source(tmp_path: Path, *, encrypted: bool = True) -> Path:
    source = tmp_path / "funded"
    source.mkdir()
    entry = (lambda n: {"address": f"0x{n:040x}", "keystore": {"v": 1, "alg": "aes-256-gcm", "kdf": "raw",
                                                               "iv": "aa", "ct": f"ct{n}", "tag": "bb"}}) \
        if encrypted else (lambda n: {"address": f"0x{n:040x}", "privateKey": "0x" + "11" * 32})
    stored = {"adminWallet": entry(99), "wallets": [entry(0), entry(1), entry(2)]}
    (source / "wallets.json").write_text(json.dumps(stored), encoding="utf-8")
    (source / "wallets.key").write_text("k" * 44, encoding="utf-8")
    return source


def test_curator_wallets_are_the_picked_encrypted_entries(tmp_path):
    nodes = _testnet(tmp_path, wallet_source=_wallet_source(tmp_path), wallet_indexes=(2, 1))

    nodes._create(1, overrides={}, wallets=True)
    stored = json.loads((nodes.home(1) / "wallets.json").read_text(encoding="utf-8-sig"))

    assert nodes.wallet_addresses(1) == [f"0x{2:040x}", f"0x{1:040x}"]   # the first is the agent address
    assert "adminWallet" not in stored and all("keystore" in entry for entry in stored["wallets"])
    assert (nodes.home(1) / "wallets.key").read_text(encoding="utf-8-sig") == "k" * 44


@pytest.mark.parametrize("indexes", [(0, 1), ()])
def test_curator_never_gets_the_source_nodes_own_agent_wallet(tmp_path, indexes):
    nodes = _testnet(tmp_path, wallet_source=_wallet_source(tmp_path), wallet_indexes=indexes)

    with pytest.raises(testnet.TestnetError):
        nodes._create(1, overrides={}, wallets=True)


def test_plaintext_source_wallets_are_refused(tmp_path):
    nodes = _testnet(tmp_path, wallet_source=_wallet_source(tmp_path, encrypted=False))

    with pytest.raises(testnet.TestnetError):
        nodes._create(1, overrides={}, wallets=True)


class _FakeApi:
    def __init__(self, answers):
        self.answers = list(answers)

    def call(self, method, path, body=None, *, timeout=60.0):
        answer = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _connection(peer: str, address: str) -> dict:
    return {"peerId": peer, "remoteAddr": address, "direction": "outbound",
            "transport": "relayed" if "/p2p-circuit" in address else "direct"}


def test_links_between_the_trials_nodes_are_relayed_or_named(tmp_path):
    circuit = "/ip4/203.0.113.1/tcp/9090/p2p/12D3KooWRelayOne/p2p-circuit/p2p/PeerB"
    curator = _FakeApi([{"connections": [_connection("PeerB", circuit), _connection("Core1", "/ip4/203.0.113.1")]}])
    reporter = _FakeApi([{"connections": [_connection("PeerA", "/ip4/192.168.0.2/tcp/4001/p2p/PeerA")]}])
    watcher = testnet.LinkWatcher(tmp_path, lambda: {"node1": (curator, "PeerA"), "node3": (reporter, "PeerB")})

    watcher.sample()
    summary = watcher.summary()

    assert summary["pairs"] == {"node1 - node3": {"relayed": 1, "direct": 1}}
    assert summary["relay_only"] is False
    assert summary["direct_links"][0]["from"] == "node3" and summary["direct_links"][0]["to"] == "node1"
    assert (tmp_path / "links.jsonl").read_text(encoding="utf-8-sig").count("\n") == 1


def test_arrivals_are_timed_per_node():
    later = _FakeApi([{"result": {"bindings": []}}, {"result": {"bindings": []}},
                      {"result": {"bindings": [{"o": {"type": "literal", "value": "x"}}]}}])
    never = _FakeApi([DkgError("down")])
    watcher = ArrivalWatcher({"reporter-b": later, "curator-2": never}, graph="0xabc/g", subject="urn:s",
                             timeout=3.0, interval=0.05)

    watcher.filed_at = time.time()
    watcher.start()
    wait_until(lambda: "reporter-b" in watcher.seen and "curator-2" in watcher.errors, timeout=3.0)
    result = watcher.result()
    watcher.stop()

    assert result["seconds_after_share"]["reporter-b"] is not None
    assert result["seconds_after_share"]["curator-2"] is None and "curator-2" in result["errors"]


class _CliActor:
    """An actor whose `blackbox` commands answer from a script, in order."""

    def __init__(self, tmp_path: Path, answers):
        self.name, self.node = "curator-2", NodeEndpoint("node1", "http://127.0.0.1:1", "")
        self.home = tmp_path / "actors" / "curator-2"
        self.answers = list(answers)
        self.calls = []

    def call(self, action, params=None, *, timeout=300.0, env=None):
        self.calls.append(params)
        return {"ok": True, "argv": (params or {}).get("argv"), **self.answers.pop(0)}


def test_owner_write_refused_until_synced_is_run_again(tmp_path):
    refused = {"rc": 2, "stdout": "Refused: ... 400: {\"code\":\"CONTEXT_GRAPH_NOT_WRITABLE\"}"}
    actor = _CliActor(tmp_path, [refused, {"rc": 0, "stdout": "manifest: published"}])
    cluster = SimpleNamespace(actors={"curator-2": actor}, devnet=SimpleNamespace(), links=None, testnet=True,
                              actor=lambda name: actor,
                              graph_row=lambda name: {"subscribed": True, "synced": True, "accessPolicy": "public"})
    trial = Trial(cluster, TrialReport(tmp_path), TrialState(stamp="s"))

    answer, owner_write = trial._owner_write(["curate", "publish", "x", "--yes"])

    assert answer["rc"] == 0 and len(actor.calls) == 2
    assert owner_write["owner_synced_after_s"] == 0
    assert "CONTEXT_GRAPH_NOT_WRITABLE" in owner_write["first_refusal"]


def test_keep_going_runs_a_step_whose_prerequisite_failed(tmp_path, monkeypatch):
    from blackbox_one_graph_trial.report import FAIL, PASS, SKIP, StepFailed

    def failed(self):
        raise StepFailed("the devnet did not come up")

    monkeypatch.setattr(Trial, "step_devnet", failed)
    monkeypatch.setattr(Trial, "step_graph", lambda self: {"summary": "graph made"})
    monkeypatch.setattr(Trial, "save", lambda self: None)
    cluster = SimpleNamespace(actors={}, devnet=SimpleNamespace(), links=None, testnet=False,
                              log_excerpts=lambda since: {})

    for keep_going, expected in ((False, SKIP), (True, PASS)):
        report = TrialReport(tmp_path / str(keep_going))
        Trial(cluster, report, TrialState(stamp="s"), until="graph", keep_going=keep_going).run()
        statuses = {step.key: step.status for step in report.steps}
        assert statuses == {"devnet": FAIL, "graph": expected}
    assert report.result("graph").summary.startswith("(ran although devnet did not pass)")


def test_checks_keep_going_runs_every_check_and_names_the_first_failure():
    from blackbox_one_graph_trial.report import StepFailed
    from blackbox_one_graph_trial.steps import _Checks

    def fails(summary):
        def check():
            raise StepFailed(summary, detail=summary)
        return check

    checks = _Checks(keep_going=True)
    assert checks.run("rule", lambda: {"ok": 1}) == {"ok": 1}
    checks.run("reports", fails("no reports"))
    checks.run("restart reports", fails("still no reports"))
    with pytest.raises(StepFailed) as raised:
        checks.done(extra="x")

    assert raised.value.summary.startswith("first failing check, reports: no reports")
    assert set(raised.value.evidence["failing_checks"]) == {"reports", "restart reports"}
    with pytest.raises(StepFailed, match="no reports"):
        _Checks(keep_going=False).run("reports", fails("no reports"))


# -- the realistic curator addresses, member admission and extra node config (OriginTrail/dkg#3421) ----------


def test_realistic_curator_announce_lists_private_addresses_that_take_no_connection():
    announce = testnet.realistic_announce(RELAYS, interfaces=["192.168.1.20", "100.69.1.2"])

    assert announce[0] == testnet.DEAD_ADDRESS
    assert announce[-2:] == [f"{relay}/p2p-circuit" for relay in RELAYS]
    direct = announce[:-2]
    assert {"/ip4/192.168.1.20/tcp/9", "/ip4/100.69.1.2/tcp/9", *testnet.UNREACHABLE_ADDRESSES} <= set(direct)
    assert all(address.endswith(f"/tcp/{testnet.DEAD_PORT}") for address in direct)
    assert {address.split("/")[2].split(".")[0] for address in testnet.UNREACHABLE_ADDRESSES} == {"10", "172", "100"}


def test_interface_addresses_leave_out_loopback_and_link_local():
    assert all(not ip.startswith(("127.", "169.254.")) for ip in testnet.interface_addresses())


def test_only_the_curator_announces_realistic_addresses_and_node_config_goes_on_top(tmp_path, monkeypatch):
    monkeypatch.setattr(testnet, "interface_addresses", lambda: ["192.168.1.20"])
    nodes = _testnet(tmp_path, curator_addresses="realistic", node_config={"DKG_Core_chain_cache": True})

    nodes._create(1, overrides={}, wallets=False)
    nodes._create(2, overrides={"syncSharedMemoryOnConnect": True}, wallets=False)

    assert nodes.config(1)["announceAddresses"] == testnet.realistic_announce(RELAYS, ["192.168.1.20"])
    assert nodes.config(2)["announceAddresses"] == testnet.relay_only_announce(RELAYS)
    assert nodes.config(1)["DKG_Core_chain_cache"] is True and nodes.config(2)["DKG_Core_chain_cache"] is True
    assert nodes.config(2)["syncSharedMemoryOnConnect"] is True


def test_default_curator_keeps_the_dead_loopback_announce(tmp_path):
    nodes = _testnet(tmp_path)

    nodes._create(1, overrides={}, wallets=False)

    assert nodes.config(1)["announceAddresses"] == testnet.relay_only_announce(RELAYS)
    assert "DKG_Core_chain_cache" not in nodes.config(1)


def test_connection_churn_counts_the_curators_closes_per_peer(tmp_path):
    nodes = _testnet(tmp_path)
    nodes.home(1).mkdir(parents=True)
    lines = [f"[2026-10-23T18:00:{second:02d}.000Z] Connection closed: {peer} transport={kind} duration={ms}ms addr=x"
             for second, peer, kind, ms in ((1, "AAAAAAAA", "relayed", 250), (2, "AAAAAAAA", "relayed", 240),
                                            (3, "AAAAAAAA", "relayed", 900000), (4, "BBBBBBBB", "direct", 5),
                                            (5, "CCCCCCCC", "relayed", 7))]
    (nodes.home(1) / "daemon.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    churn = nodes.connection_churn(1, {"node2": "12D3KooWAAAAAAAA", "node3": "12D3KooWBBBBBBBB"}, since=0.0)

    assert churn == {"node2": {"relayed": 3, "direct": 0, "median_relayed_ms": 250},
                     "node3": {"relayed": 0, "direct": 1, "median_relayed_ms": None}}


def test_admission_steps_follow_subscribe_and_late_join_only_when_asked():
    from blackbox_one_graph_trial.steps import STEPS, steps_for

    assert steps_for(False) == STEPS
    keys = [key for key, _title, _needs in steps_for(True)]
    assert keys.index("admit") == keys.index("subscribe") + 1
    assert keys.index("fresh-member") == keys.index("late-join") + 1
    assert len(keys) == len(STEPS) + 2


def test_a_missing_signing_key_is_fatal_unless_it_is_an_approved_members_wait():
    from blackbox_one_graph_trial.steps import _refusal

    fatal = ('{"error": {"code": "fatal", "message": "Cannot gossip SWM write for agent-gated context graph \\"g\\": '
             'no local allowed signing agent key", "retryable": false}, "state": "failed"}')
    waiting = ('Cannot gossip SWM write for agent-gated context graph "g": no local allowed signing agent key yet: '
               'agent 0xabc is approved and the curator\'s member list has not arrived')

    assert _refusal("job", fatal)["fatal"] is True
    assert _refusal("job", waiting)["fatal"] is False
    assert _refusal("create", "400: CONTEXT_GRAPH_NOT_WRITABLE")["fatal"] is False


def test_node_config_pairs_are_json_values_or_strings():
    from blackbox_one_graph_trial.runner import _node_config

    assert _node_config(["DKG_Core_chain_cache=true", "name=bb", "limits={\"a\": 1}"]) == {
        "DKG_Core_chain_cache": True, "name": "bb", "limits": {"a": 1}}
    with pytest.raises(ValueError):
        _node_config(["no-separator"])


def test_an_admission_passes_only_for_a_prompt_unrefused_write_that_reaches_every_reader():
    from blackbox_one_graph_trial.report import StepFailed
    from blackbox_one_graph_trial.steps import _admission_text, _judge_admission

    def evidence(after, fatal=False, arrivals=None):
        return {"write": {"written_after_s": after, "fatal": fatal, "tries": 2, "caller_involved_after_s": 3.0},
                "logs": {"fatal_no_signer_key": 0}, "arrivals": {"seconds_after_share": arrivals or {"curator-2": 4.0}}}

    assert _judge_admission("reporter-c", evidence(5.0), 600.0)
    for failing, words in ((evidence(5.0, fatal=True), "fatal"), (evidence(None), "did not go through"),
                           (evidence(75.0), "75 s after"), (evidence(5.0, arrivals={"reporter-a": None}), "reporter-a"),
                           ({"failed": "the curator's node did not list it"}, "did not list")):
        with pytest.raises(StepFailed, match=words):
            _judge_admission("reporter-c", failing, 600.0)
    assert "did not go through" in _admission_text("reporter-c", evidence(None))
    assert "wrote 5 s after its approval" in _admission_text("reporter-c", evidence(5.0))
