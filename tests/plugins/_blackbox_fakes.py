"""Test doubles the Blackbox suite shares (2026-10-22).

``FakeNodeClient`` stands in for :class:`plugins.blackbox.kernel.dkg_client.DkgClient`
in tests that only need a node that answers its identity, its network and records
what was shared. Give it a *failure* to make every share raise it. The same class
was written out in full at the top of several test files (and in 42 one-off shapes
inside tests); the shared one is the place to extend.

Usage::

    client = FakeNodeClient(reporter="0x…", network="base:84532")
    client.shares                                  # [(context graph, name, quads), …]
    FakeNodeClient(reporter, network, failure=DkgError("node down")).share_knowledge_asset(...)  # raises
"""

from __future__ import annotations

from typing import Any, Optional


class FakeNodeClient:
    def __init__(self, reporter: str, network: str, *, failure: Optional[BaseException] = None) -> None:
        self.reporter, self.network, self.failure = reporter, network, failure
        self.shares: list[tuple[str, str, Any]] = []

    def agent_identity(self) -> dict[str, str]:
        return {"agentAddress": self.reporter}

    def status(self) -> dict[str, str]:
        return {"networkId": self.network}   # real nodes always report one; signing needs it (R0b)

    def share_knowledge_asset(self, cg_id: str, name: str, quads: Any, **_: Any) -> dict[str, str]:
        if self.failure is not None:
            raise self.failure
        self.shares.append((cg_id, name, quads))
        return {"state": "succeeded"}

    def query(self, *_: Any, **kw: Any) -> Any:
        return kw.get("on_error")

    def reachable(self) -> bool:
        return True
