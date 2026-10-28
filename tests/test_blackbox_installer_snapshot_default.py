"""Execute both shipped configuration writers against an idle compatible daemon."""
import os
import re
import subprocess
import sys
from pathlib import Path

import hermes_yaml as yaml
import pytest

from tests.plugins.blackbox_sync_fixtures import replies

ROOT = Path(__file__).resolve().parents[1]
GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"


def writer(platform):
    text = (ROOT / "scripts" / f"blackbox-install.{platform}").read_text()
    if platform == "sh":
        return re.search(r"^enable_and_configure\(\)\s*\{.*?<<'PYEOF'\n(.*?)^PYEOF", text, re.MULTILINE | re.DOTALL)[1]
    return re.search(r"^function Enable-AndConfigure \{.*?\$configWriter = @'\n(.*?)^'@", text, re.MULTILINE | re.DOTALL)[1]


@pytest.mark.parametrize("platform", ["sh", "ps1"])
@pytest.mark.parametrize("kind", ["fresh", "upgrade", "opt-out", "custom-graph", "custom-peer"])
def test_installer_adopts_only_unselected_standard_transport(tmp_path, platform, kind):
    home = tmp_path / "hermes"
    home.mkdir()
    path = home / "config.yaml"
    with replies([{"state": "idle", "capabilities": {"sourcePolicies": ["DKG_Core_chain_cache"]}}]) as (url, calls):
        original = {} if kind == "fresh" else {"context_graph_id": GRAPH, "dkg_url": url,
            "dkg_home": str(tmp_path / "dkg"), "detection_backend": "legacy-cache",
            "community_shadow": True, "community_auto_approve": False,
            "daily_report_limit": 17, "report": False}
        if kind == "opt-out": original["snapshot_sync"] = {"DKG_Core_chain_cache": False}
        if kind == "custom-graph": original["context_graph_id"] = "owner/custom"
        if kind == "custom-peer": original["graph_peer_id"] = "custom-peer"
        yaml.safe_dump({"plugins": {"entries": {"blackbox": original}}}, path.open("w"))
        # Use the shipped default peer without duplicating a mutable constant.
        from tests.plugins._blackbox_loader import load_blackbox
        peer = load_blackbox("kernel.constants").DEFAULT_GRAPH_PEER_ID
        args = ([str(path), "mainnet-base", GRAPH, peer, url, str(tmp_path / "dkg"), str(tmp_path / "bin"), str(ROOT)]
                if platform == "sh" else [str(path), url, str(tmp_path / "dkg"), str(tmp_path / "bin"), GRAPH, peer, str(ROOT)])
        env = {**os.environ, "HERMES_HOME": str(home), "BLACKBOX_DKG_NETWORK": "mainnet-base",
               "PYTHONPATH": str(ROOT)}
        result = subprocess.run([sys.executable, "-c", writer(platform), *args], env=env, capture_output=True, text=True, timeout=30, check=False)
        assert result.returncode == 0, result.stderr
        saved = yaml.safe_load(path.read_text())["plugins"]["entries"]["blackbox"]
    for key, value in original.items():
        assert saved[key] == value
    assert saved["report"] is False
    if kind in {"fresh", "upgrade"}:
        assert saved["snapshot_sync"] == {"on_chain_id": "14", "trusted_core_peers": [], "mode": "core-cache", "DKG_Core_chain_cache": True}
        assert [(m, p) for m, p, _ in calls] == [("GET", "/api/context-graph/snapshot-sync")]
    elif kind == "opt-out":
        assert saved["snapshot_sync"] == original["snapshot_sync"] and not calls
    else:
        assert "snapshot_sync" not in saved and not calls
