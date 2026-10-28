"""The owner node's join approver (scripts/blackbox-curator-approve.py, 2026-10-21).

It runs on the verified graph's owner node, which does not run Blackbox, so it is
a standard-library copy of the plugin's approver; the parity test below keeps the
two parsers identical (LES-029). A fake node API on loopback drives the real
script end to end: lanes registered, every pending request approved, a refused
approval reported, and an unreachable node exiting 2 — never "nothing pending".
"""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from plugins.blackbox.community.membership import pending_join_agents as plugin_parser

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-curator-approve.py"
GRAPH = "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm"
AGENT_A = "0x60f85c1bfc29E70855E1608D355250383291aeD7"
AGENT_B = "0x6cc0F62899805EbB6Ab48C2319C3745BeFF4b2AB"


def _load():
    spec = importlib.util.spec_from_file_location("blackbox_curator_approve", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


approver = _load()


@pytest.mark.parametrize("reply", [
    {"requests": [{"agentAddress": AGENT_A, "status": "pending"}, {"agentAddress": AGENT_B, "status": "approved"}]},
    {"requests": [{"agent": AGENT_B}, {"agentAddress": "0xshort", "status": "pending"}, "junk"]},
    {"requests": None},
    {"unexpected": True},
    [],
])
def test_the_script_parses_join_requests_exactly_like_the_plugin(reply):
    assert approver.pending_join_agents(reply) == plugin_parser(reply)


class _FakeNode(BaseHTTPRequestHandler):
    pending: list = []
    calls: list = []
    refuse: set = set()

    def log_message(self, *args):   # keep test output quiet
        return

    def _reply(self, status, body):
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        type(self).calls.append(("GET", self.path, self.headers.get("Authorization")))
        self._reply(200, {"contextGraphId": GRAPH, "requests": type(self).pending})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        type(self).calls.append(("POST", self.path, body))
        if self.path == "/api/sub-graph/create" and body["subGraphName"] == "reports":
            return self._reply(400, {"error": 'Sub-graph "reports" already exists'})
        if self.path.endswith("/approve-join") and body["agentAddress"] in type(self).refuse:
            return self._reply(400, {"error": "Agent is revoked"})
        return self._reply(200, {"ok": True})


@pytest.fixture
def node(tmp_path):
    _FakeNode.pending, _FakeNode.calls, _FakeNode.refuse = [], [], set()
    server = HTTPServer(("127.0.0.1", 0), _FakeNode)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    token = tmp_path / "auth.token"
    token.write_text("# node token\nsecret-token-value\n", encoding="utf-8")
    yield f"http://127.0.0.1:{server.server_port}", token
    server.shutdown()


def test_lanes_are_registered_and_every_pending_join_is_approved(node, capsys):
    url, token = node
    _FakeNode.pending = [{"agentAddress": AGENT_A, "status": "pending"}, {"agentAddress": AGENT_B, "status": "pending"}]
    assert approver.main(["--graph", GRAPH, "--url", url, "--token-file", str(token), "--ensure-lanes"]) == 0
    posts = [(path, body) for method, path, body in _FakeNode.calls if method == "POST"]
    assert [body["subGraphName"] for path, body in posts if path == "/api/sub-graph/create"] == ["reports", "sandbox"]
    assert [body["agentAddress"] for path, body in posts if path.endswith("/approve-join")] == [AGENT_A, AGENT_B]
    assert all(auth == "Bearer secret-token-value" for method, _, auth in _FakeNode.calls if method == "GET")
    out = capsys.readouterr().out
    assert "registered lane 'sandbox'" in out and f"approved {AGENT_A}" in out


def test_a_refused_approval_is_reported_and_the_rest_still_approved(node, capsys):
    url, token = node
    _FakeNode.pending = [{"agentAddress": AGENT_A, "status": "pending"}, {"agentAddress": AGENT_B, "status": "pending"}]
    _FakeNode.refuse = {AGENT_A}
    assert approver.main(["--graph", GRAPH, "--url", url, "--token-file", str(token)]) == 0
    captured = capsys.readouterr()
    assert f"approved {AGENT_B}" in captured.out and f"refused by the node: {AGENT_A}" in captured.err


def test_a_dry_run_approves_nothing(node):
    url, token = node
    _FakeNode.pending = [{"agentAddress": AGENT_A, "status": "pending"}]
    assert approver.main(["--graph", GRAPH, "--url", url, "--token-file", str(token), "--dry-run"]) == 0
    assert not [call for call in _FakeNode.calls if call[0] == "POST"]


def test_an_unreachable_node_exits_2_never_nothing_pending(tmp_path, capsys):
    token = tmp_path / "auth.token"
    token.write_text("t\n", encoding="utf-8")
    assert approver.main(["--graph", GRAPH, "--url", "http://127.0.0.1:9", "--token-file", str(token)]) == 2
    assert "could not ask the node" in capsys.readouterr().err
