#!/usr/bin/env python3
"""Owner node: admit every Blackbox node that asks to join the verified graph (2026-10-21).

Every Blackbox node joins ONE graph, the verified graph, and writes its community
statements into that graph's shared working memory (lanes ``reports`` and
``sandbox``). The graph is registered with a CURATED publish policy, so its owner
keeps shared-memory writes only from agents on its sync allowlist. This script
runs on the owner node (systemd timer, once a minute) and:

1. makes sure the two lanes exist (``--ensure-lanes``; idempotent);
2. reads the pending join requests and approves each one.

Approval adds the agent to the SYNC allowlist only. It grants no publish right:
verifiable memory of a curated graph accepts publishes only from the graph's
publish authority (checked on chain). Trust stays read-side: reports are signed,
counted by verified author, and community data only ever flags.

Standard library only: the owner node runs the bare DKG node, not Blackbox.
The pending-request parser mirrors ``plugins/blackbox/community/membership/``
``pending_join_agents`` (parity test: tests/test_blackbox_curator_approve.py).

Usage (on the owner node)::

    blackbox-curator-approve.py --graph 0x37b1…/agent-blackbox-vm --ensure-lanes
    blackbox-curator-approve.py --graph … --dry-run      # list, approve nothing

Exit status: 0 = the node answered (approved or nothing to do); 2 = the node could
not be asked (down, busy, refused) — never read as "nothing pending" (LES-011).
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_URL = "http://127.0.0.1:8900"
DEFAULT_TOKEN_FILE = Path.home() / ".dkg" / "auth.token"
LANES = ("reports", "sandbox")
TIMEOUT_S = 30.0


class NodeError(Exception):
    """The node did not give a usable answer (transport error, HTTP error, bad JSON)."""


def read_token(path: Path) -> str:
    """The first non-blank, non-comment line of the node's auth token file."""
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            return line
    raise NodeError(f"no token in {path}")


def call(url: str, token: str, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
    """One authenticated JSON request to the node's API."""
    data = json.dumps(body).encode("utf-8") if body is not None else None
    request = urllib.request.Request(url.rstrip("/") + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json",
                                              "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:   # loopback API, not user input
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise NodeError(f"{method} {path} -> {exc.code}: {exc.read()[:300].decode('utf-8', 'replace')}") from exc
    except (urllib.error.URLError, OSError, TimeoutError) as exc:
        raise NodeError(f"{method} {path}: {exc}") from exc
    try:
        return json.loads(raw) if raw else {}
    except ValueError as exc:
        raise NodeError(f"{method} {path}: not JSON") from exc


def pending_join_agents(reply: object) -> list[str]:
    """Pure: the agent addresses of the PENDING requests in a ``join-requests`` reply."""
    rows = reply.get("requests") if isinstance(reply, dict) else None
    out: list[str] = []
    for row in rows or []:
        if not isinstance(row, dict) or str(row.get("status") or "pending").lower() != "pending":
            continue
        agent = str(row.get("agentAddress") or row.get("agent") or "")
        if agent.startswith("0x") and len(agent) == 42:
            out.append(agent)
    return out


def ensure_lanes(url: str, token: str, graph: str) -> list[str]:
    """Register each lane on *graph*; returns the lanes created now (an existing lane is fine)."""
    created = []
    for lane in LANES:
        try:
            call(url, token, "POST", "/api/sub-graph/create", {"contextGraphId": graph, "subGraphName": lane})
            created.append(lane)
        except NodeError as exc:
            if "already exists" not in str(exc):
                raise
    return created


def approve_pending(url: str, token: str, graph: str, dry_run: bool = False) -> tuple[list[str], list[str]]:
    """Approve every pending join request on *graph*: (approved, refused-with-reason)."""
    encoded = urllib.parse.quote(graph, safe="")
    pending = pending_join_agents(call(url, token, "GET", f"/api/context-graph/{encoded}/join-requests"))
    approved: list[str] = []
    refused: list[str] = []
    for agent in pending:
        if dry_run:
            approved.append(agent)
            continue
        try:
            call(url, token, "POST", f"/api/context-graph/{encoded}/approve-join", {"agentAddress": agent})
            approved.append(agent)
        except NodeError as exc:   # e.g. a revoked agent: the owner re-adds it by hand (add-agent)
            refused.append(f"{agent}: {exc}")
    return approved, refused


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--graph", required=True, help="the verified graph's id, e.g. 0x37b1…/agent-blackbox-vm")
    parser.add_argument("--url", default=DEFAULT_URL, help=f"the node API (default {DEFAULT_URL})")
    parser.add_argument("--token-file", type=Path, default=DEFAULT_TOKEN_FILE)
    parser.add_argument("--ensure-lanes", action="store_true", help="register the reports and sandbox lanes first")
    parser.add_argument("--dry-run", action="store_true", help="list pending requests, approve nothing")
    args = parser.parse_args(argv)
    try:
        token = read_token(args.token_file)
        if args.ensure_lanes:
            for lane in ensure_lanes(args.url, token, args.graph):
                print(f"registered lane {lane!r} on {args.graph}")
        approved, refused = approve_pending(args.url, token, args.graph, args.dry_run)
    except (NodeError, OSError) as exc:
        print(f"could not ask the node: {exc}", file=sys.stderr)
        return 2
    verb = "would approve" if args.dry_run else "approved"
    for agent in approved:
        print(f"{verb} {agent}")
    for line in refused:
        print(f"refused by the node: {line}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
