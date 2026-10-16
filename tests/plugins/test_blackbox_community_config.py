"""B2 contract: the community graph gets an address and a real switch.

Covers the config layer of the community-graph build: precedence of the
``community_graph_id`` resolution (env → config entry → shipped default),
the ``community_enabled`` single-gate truth table, the live ``report`` /
``daily_report_limit`` keys (KI-002), the empty-default launch-safety rule
(KI-035), and the report-threshold severity edges.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.kernel import config as bb_config
from plugins.blackbox.kernel import constants


DEV_GRAPH = "0x51E5dE758A45c8b64048E29918421F0bdD6D5d5C/agent-blackbox-community-dev"


@pytest.fixture
def clean_env(monkeypatch):
    """Blank every Blackbox env override so precedence tests start neutral."""
    for var in (
        "BLACKBOX_REPORT",
        "BLACKBOX_COMMUNITY_GRAPH_ID",
        "BLACKBOX_DAILY_REPORT_LIMIT",
        "BLACKBOX_REPORT_MIN_SEVERITY",
    ):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


def _load_with_entry(monkeypatch, entry):
    monkeypatch.setattr(bb_config, "_blackbox_entry", lambda: dict(entry))
    return bb_config.load_blackbox_config()


# ---------------------------------------------------------------------------
# community_graph_id precedence: env wins, entry second, default third
# ---------------------------------------------------------------------------


def test_env_override_wins_over_entry(clean_env):
    clean_env.setenv("BLACKBOX_COMMUNITY_GRAPH_ID", DEV_GRAPH)
    cfg = _load_with_entry(clean_env, {"community_graph_id": "0xother/graph"})
    assert cfg.community_graph_id == DEV_GRAPH


def test_entry_wins_over_default(clean_env):
    cfg = _load_with_entry(clean_env, {"community_graph_id": DEV_GRAPH})
    assert cfg.community_graph_id == DEV_GRAPH


def test_default_is_shipped_constant(clean_env):
    cfg = _load_with_entry(clean_env, {})
    assert cfg.community_graph_id == constants.DEFAULT_COMMUNITY_GRAPH_ID


def test_the_shipped_default_is_the_production_community_graph(clean_env):
    """KI-035 launch-safety rule: a release never points the fleet at a dev or
    test graph. The shipped default is the production graph, owned by the
    Umanitek wallet, and its owner peer ships with it (KI-216: both or neither)."""
    graph = constants.DEFAULT_COMMUNITY_GRAPH_ID
    assert graph == "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-community"
    assert not any(word in graph.lower() for word in ("test", "dev", "sim", "bench", "demo"))
    assert constants.DEFAULT_COMMUNITY_GRAPH_PEER_ID.startswith("12D3KooW")
    assert bool(constants.DEFAULT_COMMUNITY_GRAPH_PEER_ID) == bool(constants.DEFAULT_COMMUNITY_GRAPH_ID)


def test_a_fresh_install_reads_the_community_graph_and_shares_only_after_opting_in(clean_env):
    """A fresh install reads the production community graph but does not share:
    sharing is opt-in (2026-10-16); `report: true` (what --enable-sharing writes) turns it on."""
    cfg = _load_with_entry(clean_env, {})
    assert cfg.community_graph_id == constants.DEFAULT_COMMUNITY_GRAPH_ID
    assert cfg.report is False and cfg.community_enabled is False
    assert _load_with_entry(clean_env, {"report": True}).community_enabled is True


# ---------------------------------------------------------------------------
# community_enabled truth table — the single gate every write path uses
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("report", "graph_id", "expected"),
    [
        (True, DEV_GRAPH, True),
        (True, "", False),  # no address → dormant, even with sharing on
        (True, "   ", False),  # whitespace is not an address
        (False, DEV_GRAPH, False),  # operator off-switch is absolute
        (False, "", False),
    ],
)
def test_community_enabled_truth_table(report, graph_id, expected):
    cfg = bb_config.BlackboxConfig(report=report, community_graph_id=graph_id)
    assert cfg.community_enabled is expected


# ---------------------------------------------------------------------------
# report + daily_report_limit are LIVE keys (KI-002 part 1)
# ---------------------------------------------------------------------------


def test_report_key_is_live_from_entry(clean_env):
    cfg = _load_with_entry(clean_env, {"report": True})
    assert cfg.report is True


def test_report_env_override_wins(clean_env):
    clean_env.setenv("BLACKBOX_REPORT", "true")
    cfg = _load_with_entry(clean_env, {"report": False})
    assert cfg.report is True


def test_report_defaults_off(clean_env):
    """Community sharing is opt-in (2026-10-16, Hermes plugin catalog review): `report` is off
    unless the operator turned it on — in config.yaml or through BLACKBOX_REPORT."""
    assert _load_with_entry(clean_env, {}).report is False
    clean_env.setenv("BLACKBOX_REPORT", "1")
    assert _load_with_entry(clean_env, {}).report is True


def test_daily_report_limit_has_real_default(clean_env):
    cfg = _load_with_entry(clean_env, {})
    assert cfg.daily_report_limit == constants.DEFAULT_DAILY_REPORT_LIMIT
    assert cfg.daily_report_limit > 0


def test_daily_report_limit_configurable_and_never_negative(clean_env):
    assert _load_with_entry(clean_env, {"daily_report_limit": 5}).daily_report_limit == 5
    # Refine R1 (plan §07): the cap can no longer be switched off — 0 or below means the default.
    assert _load_with_entry(clean_env, {"daily_report_limit": -3}).daily_report_limit == 100


# ---------------------------------------------------------------------------
# report threshold severity edges
# ---------------------------------------------------------------------------


def test_the_daily_cap_defaults_to_100_and_cannot_be_switched_off(clean_env):
    """Refine R1: client hygiene (20/day, raised to 100 on 2026-10-12); `0` used to
    mean NO cap — the very value the installers wrote to make the allowance "inert"."""
    assert constants.DEFAULT_DAILY_REPORT_LIMIT == 100
    assert _load_with_entry(clean_env, {"daily_report_limit": 0}).daily_report_limit == 100
    clean_env.setenv("BLACKBOX_DAILY_REPORT_LIMIT", "0")
    assert _load_with_entry(clean_env, {}).daily_report_limit == 100


def test_allow_report_with_zero_still_caps(clean_env, tmp_path):
    from plugins.blackbox import audit
    clean_env.setenv("BLACKBOX_HOME", str(tmp_path / "bbhome"))
    allowed = [audit.allow_report(0) for _ in range(constants.DEFAULT_DAILY_REPORT_LIMIT + 5)]
    assert allowed.count(True) == constants.DEFAULT_DAILY_REPORT_LIMIT


def test_report_threshold_exactly_at_floor():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("high") is True


def test_report_threshold_below_floor():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("medium") is False


def test_report_threshold_above_floor_and_unknown():
    cfg = bb_config.BlackboxConfig(report_min_severity="high")
    assert cfg.meets_report_threshold("critical") is True
    assert cfg.meets_report_threshold("nonsense") is False
