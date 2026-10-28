"""A shield's sandbox self-tests: what an agent could attempt on THIS machine, for the Playground.

A shield that offers self-tests signs a builder up with :data:`SELF_TESTS` (a function of
its current mode returning :class:`SelfTest` records), the way it hands the kernel its
other readers — by injection, so the registry never imports a shield's internals. Each
test is an attempt the Playground hands to the real pre-tool check (``guard.on_pre_tool_call``)
inside ``audit.sandbox_run()`` — nothing is executed, nothing leaves the machine, and the
finding stays in the sandbox's own logs.

The attempts are built at run time from what the shield finds here (its key-store folders)
and from values made fresh for each list (a generated seed phrase or key), never from attack
strings shipped in the plugin: Hermes's plugin install scanner reads shipped attack strings
as attacks (LES-058).

Usage::

    SELF_TESTS.register("trader", self_tests.build)        # in the shield's __init__
    from plugins.blackbox import shields
    for shield, test in shields.self_tests():                # anywhere else
        test.tool, test.args          # what the agent would hand its tool
        test.shown                    # the same attempt as the dashboard shows it (secrets masked)
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Callable, Mapping

from .contract import ShieldMode

#: A tool argument: a path or command text, or a list of URLs (the web tools take ``urls``).
ToolArg = str | tuple[str, ...]


@dataclass(frozen=True)
class SelfTest:
    """One attempt a shield offers to run through the real check.

    * ``id`` — stable for this machine's layout (the Playground runs a test by id);
    * ``group`` / ``group_name`` — what the dashboard groups by (a wallet, "Seed phrases and keys");
    * ``title`` — the attempt in plain words ("Agent opens MetaMask's vault in Chrome");
    * ``tool`` / ``args`` — exactly what the agent would hand its tool;
    * ``shown`` — the attempt as the page shows it, with any generated secret masked;
    * ``expect`` — what this shield does when it is on and the item is chosen, in block mode
      (``blocked`` or ``flagged``);
    * ``note`` — why the shield would let it through right now ("" when it is guarded).
    """

    id: str
    group: str
    group_name: str
    title: str
    tool: str
    args: Mapping[str, ToolArg] = field(default_factory=dict)
    shown: str = ""
    expect: str = "blocked"
    note: str = ""

    def hook_args(self) -> dict[str, object]:
        """``args`` as the hook receives them (lists, not tuples)."""
        return {key: list(value) if isinstance(value, tuple) else value for key, value in self.args.items()}

    def as_json(self) -> dict[str, object]:
        """What the dashboard lists — never ``args``, which may hold a generated secret."""
        return {"id": self.id, "group": self.group, "group_name": self.group_name, "title": self.title,
                "shown": self.shown, "expect": self.expect, "note": self.note}


Builder = Callable[[ShieldMode], tuple[SelfTest, ...]]


class SelfTestBuilders:
    """The shields' self-test builders by shield id (Registry; one lock)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._builders: dict[str, Builder] = {}

    def register(self, shield_id: str, builder: Builder) -> None:
        """Sign *builder* up for *shield_id* (a second call replaces the first)."""
        with self._lock:
            self._builders[shield_id] = builder

    def builder(self, shield_id: str) -> Builder | None:
        """*shield_id*'s builder, or None when it offers no self-tests."""
        with self._lock:
            return self._builders.get(shield_id)


#: The one registry of self-test builders (Global Object).
SELF_TESTS = SelfTestBuilders()
