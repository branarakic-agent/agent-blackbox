"""A fresh node syncs the verified graph and its community side by side, and never
re-subscribes it on every run (KI-449).

Bench 2026-10-22, DKG 10.0.25: every subscribe that included shared memory restarted the
node's shared-memory catch-up, and Blackbox subscribed again from every fresh process
(each `blackbox sync` run, each dashboard restart), while the node ran with ONE sync slot
— so a fresh node's verified download crawled (30 of 565 assets in 40 min). The node now
runs with its own default of 10 slots (sync/node_profile.py), the community subscription
is added at once and ONCE per node, and sync subscribes only when the node says the graph
is not subscribed. With that, the whole graph arrived in about 30 minutes with the
community syncing alongside. Nothing is requested when the node's listing cannot be read
(LES-011).
"""

from __future__ import annotations

from types import SimpleNamespace

from plugins.blackbox.community.membership import CommunityMembership
from plugins.blackbox.community.membership.readiness import GraphReadiness
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.sync import native, node_profile

GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"


def _readiness(tmp_path):
    return GraphReadiness(store=lambda: tmp_path / "verified_ready.json", clock=lambda: 1_000.0)


class _Node:
    """A member's node: its listing says whether the graph is subscribed; records subscribes."""

    def __init__(self, listed=True, readable=True):
        self.listed, self.readable, self.subscribes = listed, readable, []

    def context_graphs(self):
        if not self.readable:
            raise OSError("node busy")
        row = {"id": GRAPH, "subscribed": True, "accessPolicy": "public",
               "onChainId": "14", "onChain": {"publishPolicy": "curated"}, "callerInvolved": True}
        return [row] if self.listed else []

    def subscribe_context_graph(self, graph, include_shared_memory=True):
        self.subscribes.append(include_shared_memory)
        self.listed = True
        return {"subscribed": graph, "catchup": {"status": "queued", "includeWorkspace": include_shared_memory}}

    def agent_identity(self):
        return {"agentAddress": "0x" + "60" * 20}


def _cfg():
    return SimpleNamespace(context_graph_id=GRAPH, graph_peer_id="12D3KooWowner", report=False)


# --------------------------------------------------------------------------- the record


def test_the_record_survives_a_new_process(tmp_path):
    first = _readiness(tmp_path)
    assert not first.shared_memory_added(GRAPH)
    first.mark_shared_memory_added(GRAPH)
    assert _readiness(tmp_path).shared_memory_added(GRAPH)


def test_an_unreadable_record_means_not_added_yet(tmp_path):
    (tmp_path / "verified_ready.json").write_text("not json", encoding="utf-8")
    assert not _readiness(tmp_path).shared_memory_added(GRAPH)


# --------------------------------------------------------------------------- membership


def test_the_community_is_added_at_once_and_once_per_node(tmp_path):
    node = _Node(listed=True)
    assert CommunityMembership(readiness=_readiness(tmp_path)).ensure(node, _cfg())[0]
    assert node.subscribes == [True]                    # at once: no wait for the verified graph
    # A fresh process (a `blackbox sync` run, a dashboard restart) only confirms it.
    assert CommunityMembership(readiness=_readiness(tmp_path)).ensure(node, _cfg())[0]
    assert node.subscribes == [True]


def test_an_unreadable_listing_requests_nothing(tmp_path):
    readiness = _readiness(tmp_path)
    readiness.mark_shared_memory_added(GRAPH)
    node = _Node(listed=True, readable=False)
    ok, detail = CommunityMembership(readiness=readiness).ensure(node, _cfg())
    assert not ok and "could not be read" in detail and node.subscribes == []


# --------------------------------------------------------------------------- sync (native route)


def _seen():
    return native._Observation()


def test_sync_subscribes_only_when_the_node_says_it_is_not_subscribed():
    cfg = BlackboxConfig()
    fresh = _Node(listed=False)
    native._subscribe(fresh, cfg, _seen())
    assert len(fresh.subscribes) == 1
    already = _Node(listed=True)
    seen = _seen()
    native._subscribe(already, cfg, seen)
    assert already.subscribes == [] and seen.subscribed


def test_sync_requests_nothing_when_the_listing_cannot_be_read():
    node = _Node(readable=False)
    seen = _seen()
    native._subscribe(node, BlackboxConfig(), seen)
    assert node.subscribes == [] and not seen.subscribed and "could not be read" in seen.error


# --------------------------------------------------------------------------- the node's sync slots


def test_the_node_runs_with_its_own_default_sync_slots():
    """One slot let the community catch-ups starve the verified download (KI-449)."""
    settings = node_profile.node_sync_settings(BlackboxConfig())
    assert settings["DKG_SYNC_GLOBAL_MAX_INFLIGHT"] == "10"
    assert settings["DKG_SYNC_GLOBAL_QUEUE_LIMIT"] == "20"
