"""Transport admission preserves protections; the owned job proves cores and coverage."""
import argparse
from copy import deepcopy

import pytest
from _blackbox_loader import load_blackbox
from tests.plugins.blackbox_sync_fixtures import replies

ready = load_blackbox("sync.snapshot_readiness")
profile = load_blackbox("setup.sync_profile")
yaml_files = load_blackbox("kernel.yaml_files")
config = load_blackbox("kernel.config")


@pytest.mark.parametrize("job", [{}, {"state": "running"}, {"state": "idle"},
    {"state": "idle", "capabilities": {}},
    {"state": "idle", "capabilities": {"sourcePolicies": ["advertised-core"]}},
    {"state": "idle", "capabilities": {"sourcePolicies": "DKG_Core_chain_cache"}}])
def test_incompatible_daemon_never_selects_snapshot_transport(tmp_path, job):
    with replies([job]) as (url, calls):
        assert ready.defaults({"dkg_url": url, "dkg_home": str(tmp_path)}) == {}
    assert [method for method, _, _ in calls] == ["GET"]


@pytest.mark.parametrize("sharing", [False, True])
@pytest.mark.parametrize("backend", ["legacy-cache", "dkg"])
def test_first_sync_does_not_require_a_previous_sync_or_change_protections(tmp_path, sharing, backend):
    with replies([{"state": "idle", "capabilities": {"sourcePolicies": ["DKG_Core_chain_cache"]}}]) as (url, calls):
        entry = {"dkg_url": url, "dkg_home": str(tmp_path), "report": sharing,
                 "community_shadow": True, "daily_report_limit": 10, "detection_backend": backend}
        before = deepcopy(entry)
        selected = ready.defaults(entry)
        cfg = config.load_blackbox_config(entry={**entry, **selected})
    assert entry == before and "detection_backend" not in selected
    assert cfg.detection_backend == backend and cfg.report is sharing
    assert cfg.community_shadow and cfg.daily_report_limit == 10
    assert cfg.snapshot_sync.source_policy == "DKG_Core_chain_cache"
    assert [(method, path) for method, path, _ in calls] == [("GET", ready.PATH)]


def test_explicit_setup_preserves_community_protection_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    original = {"report": False, "community_shadow": True, "daily_report_limit": 17}
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": original}}})
    profile.configure(argparse.Namespace(dkg_core_chain_cache=True))
    saved = yaml_files.load_yaml(path)["plugins"]["entries"]["blackbox"]
    assert {key: saved[key] for key in original} == original
    cfg = config.load_blackbox_config()
    assert cfg.detection_backend == "legacy-cache" and cfg.snapshot_sync


def test_existing_explicit_profile_is_never_automatically_replaced(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    path = tmp_path / "config.yaml"
    yaml_files.dump_yaml(path, {"plugins": {"entries": {"blackbox": ready.requested_profile()}}})
    before = path.read_bytes()
    profile.configure(argparse.Namespace())
    assert path.read_bytes() == before


@pytest.mark.parametrize("address", ["http://127.0.0.1:1", "https://remote.invalid:9320"])
def test_unreachable_or_nonlocal_daemon_cannot_enable_default(tmp_path, address):
    assert ready.defaults({"dkg_url": address, "dkg_home": str(tmp_path)}) == {}
