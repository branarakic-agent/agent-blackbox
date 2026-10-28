"""Core snapshot transport retains the community reader and per-profile trust."""
import argparse
from dataclasses import replace
from unittest.mock import Mock

from _blackbox_loader import load_blackbox
from tests.plugins.blackbox_sync_fixtures import replies, completed_job

config = load_blackbox("kernel.config")
core = load_blackbox("sync.core_snapshot")
settings = load_blackbox("kernel.snapshot_config")
client_module = load_blackbox("kernel.dkg_client")
community = load_blackbox("ruleset.direct.community")
compiler = load_blackbox("ruleset.compiler")
membership = load_blackbox("community.membership")


def configured(tmp_path):
    return config.BlackboxConfig(dkg_home=str(tmp_path),
        snapshot_sync=settings.SnapshotSyncConfig("14", (), "core-cache", "DKG_Core_chain_cache"))


def test_first_owned_snapshot_uses_existing_compiler_after_coverage(tmp_path, monkeypatch):
    cfg = configured(tmp_path)
    done = completed_job()
    running = {"id": done["id"], "state": "running", "request": done["request"]}
    calls = []
    def compile_rules(actual, client, **kwargs):
        calls.append((actual, kwargs))
        rs = compiler.Ruleset(context_graph_id=actual.context_graph_id)
        rs.dependency["pkg"] = {"source": "public"}
        return rs
    monkeypatch.setattr(core.ruleset, "refresh", compile_rules)
    monkeypatch.setattr(core.ruleset, "ready_sample", Mock(side_effect=AssertionError("must keep compiled reader")))
    monkeypatch.setattr(core, "POLL_SECONDS", 0)
    with replies([{"state": "idle", "capabilities": done["capabilities"]}, running, done]) as (url, http):
        cfg = replace(cfg, dkg_url=url)
        assert core.run(core.SnapshotSyncClient(cfg), cfg, argparse.Namespace(wait=True, require_rules=True, timeout=5)) == 0
    assert len([c for c in http if c[0] == "POST"]) == 1
    assert all(actual == cfg for actual, _ in calls)
    assert calls[-1][1]["force_query"] is True
    state = core.state.read_for_graph(cfg.context_graph_id)
    assert state["count_kind"] == "compiled-rules" and state["graph_complete"] is True


def test_core_cache_query_consent_is_bound_to_one_profile_and_graph(tmp_path):
    cfg = configured(tmp_path)
    with replies([{"bindings": []}] * 5) as (url, calls):
        cfg = replace(cfg, dkg_url=url)
        client = client_module.DkgClient(url=url, dkg_home=cfg.dkg_home, config=cfg)
        client.query("SELECT * WHERE {}", cfg.context_graph_id)
        client.query("SELECT * WHERE {}", "other/graph")
        client_module.DkgClient(url=url, dkg_home=str(tmp_path / "other"), config=cfg).query("SELECT * WHERE {}", cfg.context_graph_id)
        client_module.DkgClient(url=url, dkg_home=cfg.dkg_home, config=replace(cfg, dkg_url="http://127.0.0.1:1")).query("SELECT * WHERE {}", cfg.context_graph_id)
        client_module.DkgClient(url=url, dkg_home=str(tmp_path / "other")).query("SELECT * WHERE {}", cfg.context_graph_id)
    assert calls[0][2]["chainEvidenceMode"] == "core-cache"
    assert all("chainEvidenceMode" not in call[2] for call in calls[1:])


def test_community_subscription_waits_for_snapshot_without_losing_existing_reads(tmp_path):
    cfg = configured(tmp_path)
    client = Mock()
    client.request.return_value = {"state": "running"}
    member = membership.CommunityMembership()
    ok, _ = member.ensure(client, cfg)
    assert not ok
    client.subscribe_context_graph.assert_not_called()
    client.request_join.assert_not_called()


def test_direct_community_persists_retention_and_never_exports_public_rules(tmp_path, monkeypatch):
    cfg = replace(configured(tmp_path), detection_backend="dkg")
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile-a"))
    seen = []
    def apply(rs, client, actual, prior):
        seen.append(prior)
        rs.community = {"ioc:bad.example": {"counted": 2, "firstSeen": 123, "stage": "FLAG"}}
        rs.community_empty_since = 17
    monkeypatch.setattr(community.community_tier, "apply_community_tier", apply)
    assert community.refresh(cfg, Mock())
    assert community.refresh(cfg, Mock())
    assert seen[1].community["ioc:bad.example"]["firstSeen"] == 123
    assert community.read(cfg).community_empty_since == 17
    assert not (tmp_path / "profile-a/blackbox/ruleset.json").exists()
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile-b"))
    assert community.read(cfg) is None
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "profile-a"))
    assert community.read(replace(cfg, context_graph_id="other/graph")) is None
    prior = community._path().read_bytes()
    def unavailable(rs, *args):
        rs.community_read_unavailable = True
    monkeypatch.setattr(community.community_tier, "apply_community_tier", unavailable)
    assert not community.refresh(cfg, Mock())
    assert community._path().read_bytes() == prior


def test_switching_to_direct_keeps_community_history_but_not_public_rules(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    cfg = configured(tmp_path)
    prior = compiler.Ruleset(context_graph_id=cfg.context_graph_id)
    prior.community = {"ioc:bad.example": {"firstSeen": 123, "source": "community"}}
    prior.dependency["public-only"] = {"source": "public"}
    community.disk_cache._write_cache(prior)
    observed = community.read(cfg)
    assert observed.community == prior.community
    target = compiler.Ruleset(context_graph_id=cfg.context_graph_id)
    assert community.attach(target, cfg)
    assert "public-only" not in target.dependency
