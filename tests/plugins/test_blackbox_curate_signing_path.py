"""The signing choke point (trust-and-threat-lab S4, F-054).

Every signature code under ``curate/`` makes goes through
``CurateContext.sign`` / ``.cosign``, and each one appends a row to the node's
``SigningLog`` — the ledger the signature reconciler compares published
statements against. The AST guard below fails when anything else under
``curate/`` calls (or takes a handle on) a signing function, so a new verb
cannot sign without being logged.
"""

from __future__ import annotations

import ast
import dataclasses
import json
from pathlib import Path
from typing import List, Tuple

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.blackbox import killlist
from plugins.blackbox.curate import verbs
from plugins.blackbox.curate.context import KillListDraft, ManifestDraft, PromotionDraft, StatementDraft
from plugins.blackbox.curate.proposals.proposal import ProposalStore
from plugins.blackbox.curate.watch import SigningLog, SigningRow
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement
from test_blackbox_curate import VM_GRAPH, FakeNode, _ctx, _machine, curators

CURATE = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "curate"

#: ``module.function`` pairs that sign; the receiver name is how curate/ imports them.
_SIGNING_ATTRIBUTES = {("signing", "sign"), ("signing", "cosign"), ("envelope", "sign"), ("envelope", "cosign"),
                       ("promotion", "sign")}
#: Modules whose ``sign`` / ``cosign`` sign; importing one under another name would hide its calls.
_SIGNING_MODULES = {"signing", "envelope", "promotion"}
#: Functions that sign whatever module they are reached through (or imported bare).
_SIGNING_FUNCTIONS = {"sign_statement", "sign_manifest", "sign_curator_statement", "sign_kill_list",
                      "sign_migration"}
#: The only places allowed to hold them: (file under curate/, class, method).
_CHOKE_POINT = {("context.py", "CurateContext", "sign"), ("context.py", "CurateContext", "cosign")}


def _signing_references(tree: ast.AST) -> list[tuple[int, str, str]]:
    """Every reference to a signing function in *tree* as (line, enclosing
    ``Class.method`` or "", what) — a call, a bare handle (``f = signing.sign``), a
    ``from … import sign_manifest``, or a signing module imported under another name."""
    found: list[tuple[int, str, str]] = []

    def visit(node: ast.AST, owner: str) -> None:
        if isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visit_body(child, f"{node.name}.{child.name}")
                else:
                    visit(child, owner)
            return
        if isinstance(node, ast.Attribute):
            receiver = node.value.id if isinstance(node.value, ast.Name) else ""
            if (receiver, node.attr) in _SIGNING_ATTRIBUTES or node.attr in _SIGNING_FUNCTIONS:
                found.append((node.lineno, owner, f"{receiver or '…'}.{node.attr}"))
        elif isinstance(node, ast.Name) and node.id in _SIGNING_FUNCTIONS:
            found.append((node.lineno, owner, node.id))
        elif isinstance(node, ast.ImportFrom):
            source = (node.module or "").rsplit(".", 1)[-1]
            for alias in node.names:
                if alias.name in _SIGNING_FUNCTIONS or (source in _SIGNING_MODULES
                                                         and alias.name in {"sign", "cosign"}):
                    found.append((node.lineno, owner, f"import {alias.name}"))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                module = alias.name.rsplit(".", 1)[-1]
                if module in _SIGNING_MODULES and alias.asname not in (None, module):
                    found.append((node.lineno, owner, f"import {module} as {alias.asname}"))
        for child in ast.iter_child_nodes(node):
            visit(child, owner)

    def visit_body(function: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(function):
            visit(child, owner)

    visit(tree, "")
    return found


def _offenders(relative: str, source: str) -> list[str]:
    """Signing references in one curate/ file that sit outside the choke point."""
    offenders = []
    for line, owner, what in _signing_references(ast.parse(source)):
        class_name, _, method = owner.partition(".")
        if (relative, class_name, method) not in _CHOKE_POINT:
            offenders.append(f"curate/{relative}:{line} {owner + ': ' if owner else ''}{what}")
    return offenders


def _curate_sources():
    for path in sorted(CURATE.rglob("*.py")):
        yield path.relative_to(CURATE).as_posix(), path.read_text(encoding="utf-8")


# -- the AST guard ---------------------------------------------------------------


def test_nothing_under_curate_signs_outside_the_choke_point():
    offenders = [hit for relative, source in _curate_sources() for hit in _offenders(relative, source)]
    assert offenders == [], ("sign through CurateContext.sign / .cosign so the signing log sees it:\n"
                             + "\n".join(offenders))


def test_the_guard_sees_the_choke_point_itself():
    """Not vacuous: the choke point's own signing calls are found — and allowed."""
    source = (CURATE / "context.py").read_text(encoding="utf-8")
    owners = {owner for _line, owner, _what in _signing_references(ast.parse(source))}
    assert owners == {"CurateContext.sign", "CurateContext.cosign"}
    assert _offenders("context.py", source) == []


@pytest.mark.parametrize("injected", [
    "\n\ndef sneak(envelope, key):\n    return signing.sign(key, statement_type='x', environment='e', graph='g', payload={})\n",
    "\n\ndef sneak(envelope, key):\n    return signing.cosign(envelope, key)\n",
    "\n\nsneak = promotion.sign\n",
    "\n\nfrom ..kernel.signing.key_manifest import sign_manifest\n",
    "\n\ndef sneak(manifest, key):\n    return key_manifest.sign_manifest(manifest, key)\n",
    "\n\nclass CurateContext:\n    def helper(self, key):\n        return signing.sign(key)\n",
    # review of S4: the K3 migration signer, the envelope module, and an aliased signing module
    "\n\ndef sneak(migration, root):\n    return graph_migration.sign_migration(migration, root)\n",
    "\n\nfrom ..kernel.signing.graph_migration import sign_migration\n",
    "\n\ndef sneak(envelope_text, key):\n    return envelope.cosign(envelope_text, key)\n",
    "\n\nfrom ..kernel import signing as s\n",
    "\n\nimport plugins.blackbox.kernel.signing as s\n",
])
def test_a_direct_signing_call_injected_into_verbs_fails_the_guard(injected):
    source = (CURATE / "verbs.py").read_text(encoding="utf-8")
    assert _offenders("verbs.py", source) == []
    assert _offenders("verbs.py", source + injected) != []


# -- the SigningLog rows ---------------------------------------------------------


def _rows(home: Path) -> list[SigningRow]:
    return SigningLog(home / "curate" / "signing_log.jsonl").rows()


def test_every_signature_through_the_choke_point_appends_one_row(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    ctx = _ctx(FakeNode(), curators["manifest"])
    payload = {"identifier": "dep:npm:evil-pkg@1.0.0", "name": "TOP-SECRET-PAYLOAD-NAME", "severity": "critical"}
    envelope = ctx.sign(PromotionDraft(payload, sequence=4), curators["a"])
    cosigned = ctx.cosign(envelope, curators["b"])

    first, second = _rows(tmp_path / "A")
    assert (first.kind, first.action, first.key) == (CuratorStatement.PROMOTION.value, "sign",
                                                     signing.public_key_hex(curators["a"]))
    assert (second.kind, second.action, second.key) == (CuratorStatement.PROMOTION.value, "cosign",
                                                        signing.public_key_hex(curators["b"]))
    assert first.digest == second.digest == signing.content_id(cosigned) == signing.content_id(envelope)
    assert first.at > 0 and second.at >= first.at
    raw = (tmp_path / "A" / "curate" / "signing_log.jsonl").read_text(encoding="utf-8")
    for line in raw.splitlines():
        assert set(json.loads(line)) == {"kind", "digest", "key", "action", "at"}
    assert "TOP-SECRET-PAYLOAD-NAME" not in raw and "evil-pkg" not in raw and envelope.to_text() not in raw


def test_each_draft_family_is_signed_and_logged(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    log = SigningLog(tmp_path / "elsewhere.jsonl")
    ctx = dataclasses.replace(_ctx(FakeNode(), curators["manifest"]), signing_log=log)
    kill_list = killlist.KillList(version=1, day="2026-10-11", entries=(killlist.KillEntry.from_json(
        {"registry": "skill", "identifier": "evil-skill", "action": "disable", "reason": "malware"}),))
    root = Ed25519PrivateKey.generate()
    signed = [
        ctx.sign(StatementDraft(CuratorStatement.IN_REVIEW, "dep:npm:evil-pkg@1.0.0", {}, sequence=1, graph=VM_GRAPH),
                 curators["a"]),
        ctx.sign(KillListDraft(kill_list, VM_GRAPH), curators["a"]),
        ctx.sign(ManifestDraft(curators["manifest"]), root),          # root-signed: no trusted manifest needed
    ]
    assert [(row.kind, row.digest) for row in log.rows()] == [(e.statement_type, signing.content_id(e)) for e in signed]
    assert not (tmp_path / "A" / "curate" / "signing_log.jsonl").exists()   # the injected log, not the default


def test_a_refused_signature_logs_nothing(monkeypatch, tmp_path, curators):
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    ctx = _ctx(FakeNode(), curators["manifest"])
    envelope = ctx.sign(PromotionDraft({"identifier": "x"}, sequence=1), curators["a"])
    with pytest.raises(ValueError):
        ctx.cosign(envelope, curators["a"])                     # this key already signed it
    with pytest.raises(ValueError):
        _ctx(FakeNode(), None).sign(PromotionDraft({"identifier": "x"}, sequence=1), curators["a"])   # no manifest
    assert [row.action for row in _rows(tmp_path / "A")] == ["sign"]


def test_the_two_key_verbs_log_on_each_machine(monkeypatch, tmp_path, curators):
    """End to end: A's propose logs A's first signature; B's approve logs B's co-signature."""
    node = FakeNode()
    _machine(monkeypatch, tmp_path, "A", curators["a"])
    proposal = verbs.propose_kill_list(_ctx(node, curators["manifest"]), ProposalStore(),
                                       entries=[{"registry": "skill", "identifier": "evil-skill", "action": "disable",
                                                 "reason": "malware"}])
    _machine(monkeypatch, tmp_path, "B", curators["b"])
    store_b = ProposalStore()
    store_b.save(proposal)
    verbs.approve(_ctx(node, curators["manifest"]), store_b, proposal.id, evidence="", typed_code=None, yes=True)

    (a_row,), (b_row,) = _rows(tmp_path / "A"), _rows(tmp_path / "B")
    assert (a_row.action, a_row.key) == ("sign", signing.public_key_hex(curators["a"]))
    assert (b_row.action, b_row.key) == ("cosign", signing.public_key_hex(curators["b"]))
    assert a_row.kind == b_row.kind == killlist.KILL_LIST_STATEMENT
    assert a_row.digest == b_row.digest == signing.content_id(proposal.parsed())
