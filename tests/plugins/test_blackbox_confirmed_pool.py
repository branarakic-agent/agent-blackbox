"""Community Curation C8 — the confirmed pool and the valve.

Reporters, three curator machines and a reader share one in-memory network
(``_machines``); reports are built by the product's own writer. The pool is
derived on a curator machine, exported as a bundle, and verified on a machine
that holds NOTHING but the community root key — playing both sides of the
hand-off to the verified graph's owner.
"""

from __future__ import annotations

import copy
import dataclasses
import json
from datetime import timedelta

import pytest
from _clock import utc_today
from _community_rows import GRAPH, NETWORK, Reporter, signed_row
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from _machines import SWM, Machine, share_report
from test_blackbox_authority import CFG as AUTHORITY_CFG
from test_blackbox_authority import CITED, Side
from test_blackbox_curate_community import CFG, EVIDENCE, Curators, _listing
from test_blackbox_trust_store import Store

from plugins.blackbox import community
from plugins.blackbox.community import pool
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.curate import dossier, handoff, keys, node_ui_views, verbs
from plugins.blackbox.curate.context import CurateContext
from plugins.blackbox.curate.proposal import ProposalStore
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing import key_manifest
from plugins.blackbox.kernel.signing.authority import Authority
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

IP = "ioc:ip:203.0.113.7"


def signing_manifest(manifest, root) -> str:
    """*manifest* signed by *root*, as the text a bundle carries."""
    return key_manifest.sign_manifest(manifest, root).to_text()

PACKAGE = "dep:npm:evil-pkg@1.0.0"
TODAY = utc_today().isoformat()


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)


class Valve:
    """A community with two confirmed threats: IP (alice trusted + bob unlisted) and PACKAGE (alice)."""

    def __init__(self, tmp_path, monkeypatch):
        self.team = Curators(tmp_path, monkeypatch)
        self.alice, self.bob = Reporter("0xa"), Reporter("0xb")
        with self.team.a:
            self.root = keys.root_key_store(Authority.COMMUNITY).public_key_hex()
        node = self.team.reader.node
        share_report(node, IP, self.alice, severity="high")
        share_report(node, IP, self.bob, severity="critical", ioc_context="in-tool-output")
        share_report(node, PACKAGE, self.alice)
        share_report(node, "ioc:ip:203.0.113.99", self.bob)                      # reported, never confirmed
        self.team.two_key(Kind.COUNTED_AUTHORS, f"author:{self.alice.author}", _listing(self.alice))
        self.team.two_key(Kind.CONFIRMATION, IP, {})
        self.team.two_key(Kind.CONFIRMATION, PACKAGE, {})
        self.receiver = Machine(self.team.net, tmp_path, monkeypatch, "U")      # holds nothing but what it is handed

    def ctx(self, machine=None, **kw):
        machine = machine or self.team.b
        interest = [IP, PACKAGE, f"author:{self.alice.author}", f"author:{self.bob.author}"]
        return self.team.ctx(machine, interest=interest, **kw)

    def pool(self, machine=None):
        machine = machine or self.team.b
        with machine:
            return handoff.read_live_pool(self.ctx(machine))

    def bundle(self):
        with self.team.b:
            ctx = self.ctx()
            return handoff.bundle_text(ctx, handoff.read_live_pool(ctx))

    def verify(self, text, **over):
        with self.receiver:
            return pool.verify_bundle(text, over.pop("roots", {self.root}), environment=over.pop("environment", NETWORK),
                                      graph=over.pop("graph", GRAPH), **over)


@pytest.fixture
def valve(tmp_path, monkeypatch):
    return Valve(tmp_path, monkeypatch)


# ------------------------------------------------------------------ the pool is a view


def test_the_pool_holds_each_confirmed_threat_with_its_evidence_reports_and_context(valve):
    found = valve.pool()
    assert found.unavailable == "" and [entry.identifier for entry in found.entries] == [PACKAGE, IP]
    ip = found.entries[1]
    assert (ip.evidence, ip.confirmed_day, len(ip.curators)) == (EVIDENCE, TODAY, 2)
    assert (ip.reporters, ip.trusted_voices, ip.established, ip.partner_organisations) == (2, 1, 1, 0)   # bob is unlisted
    assert (ip.category, ip.severity, ip.first_reported) == ("ioc", "critical", TODAY)                    # the highest signed severity
    assert dict(ip.fields) == {"ioc_type": "ip"}                 # the two reporters signed different contexts: not agreed
    assert len(ip.reports) == 2 and len(ip.listings) == 1
    package = found.entries[0]
    assert dict(package.fields)["package_name"] == "evil-pkg" and dict(package.fields)["kind"] == "malware"


def test_every_curator_machine_and_a_plain_reader_derive_the_same_pool(valve):
    pools = [valve.pool(machine).entries for machine in (valve.team.a, valve.team.b, valve.team.c, valve.team.reader)]
    assert pools[0] and all(entries == pools[0] for entries in pools)


def test_a_confirmation_later_rejected_leaves_the_pool_and_the_next_export(valve):
    valve.team.two_key(Kind.REJECTION, IP, {"reason": "benign"})
    assert [entry.identifier for entry in valve.pool().entries] == [PACKAGE]
    assert [entry["identifier"] for entry in json.loads(valve.bundle())["entries"]] == [PACKAGE]


def test_a_confirmation_leaves_the_pool_when_the_threats_community_lifetime_has_passed(valve):
    with valve.team.b:
        ctx = valve.ctx()
        read = community.read_verified_reports(ctx.client, ctx.cfg)
        rows = [row for _, row in community.known_curator_statements(ctx.client, ctx.cfg, [IP, PACKAGE])]
        manifest = read.curator.community.manifest

        def on(days):
            day = (utc_today() + timedelta(days=days)).isoformat()
            return [entry.identifier for entry in pool.confirmed_pool(manifest, rows, read.reports, graph=GRAPH, today=day)]
    assert on(47) == [PACKAGE, IP] and on(48) == [PACKAGE]              # an IP lives 47 days, a package 460
    assert on(460) == [PACKAGE] and on(461) == []


def test_one_curator_signature_or_an_outsiders_row_puts_nothing_in_the_pool(valve):
    other = "ioc:ip:203.0.113.50"
    share_report(valve.team.reader.node, other, valve.alice)
    with valve.team.a:
        half = verbs.propose_statement(valve.team.ctx(valve.team.a, interest=[other]), ProposalStore(),
                                       kind=Kind.CONFIRMATION, identifier=other, fields={}, evidence=EVIDENCE)
    envelope = signing.from_text(half.envelope)
    valve.team.reader.node.share_knowledge_asset(GRAPH, "one-key-confirmation", cs.statement_quads(envelope))
    with valve.team.b:
        ctx = valve.team.ctx(valve.team.b, interest=[other, IP, PACKAGE])
        read = community.read_verified_reports(ctx.client, ctx.cfg)
        rows = [row for _, row in community.known_curator_statements(ctx.client, ctx.cfg, [other, IP, PACKAGE])]
        entries = pool.confirmed_pool(read.curator.community.manifest, rows, read.reports, graph=GRAPH)
    assert any(row["identifier"] == other for row in rows)              # the half-signed row IS on the graph
    assert other not in [entry.identifier for entry in entries]


def test_rewritten_copies_of_a_statement_on_the_graph_put_one_text_in_the_pool(valve):
    """Anyone can publish a genuine statement again as a different text (KI-266); the pool, and so the
    bundle, holds each statement once, as the same text on every machine."""
    before = valve.pool().entries
    with valve.team.b:
        rows = [row for _, row in community.known_curator_statements(valve.team.b.node, CFG, [IP, f"author:{valve.alice.author}"])]
    for n, row in enumerate(rows):
        document = json.loads(row["signedStatement"])
        rewritten = json.dumps({**document, "note": "x"}, indent=1)                    # verifies, another text
        quads = [{"subject": row["r"], "predicate": predicate, "object": json.dumps(value)} for predicate, value in (
            ("http://umanitek.ai/ontology/guardian/identifier", row["identifier"]),
            ("http://umanitek.ai/ontology/guardian/signedStatement", rewritten))]
        quads.append({"subject": row["r"], "predicate": "http://www.w3.org/1999/02/22-rdf-syntax-ns#type",
                      "object": "<http://umanitek.ai/ontology/guardian/CuratorStatement>"})
        valve.team.reader.node.share_knowledge_asset(GRAPH, f"rewritten-copy-{n}", quads)
    with valve.team.b:
        seen = [row for _, row in community.known_curator_statements(valve.team.b.node, CFG, [IP, f"author:{valve.alice.author}"])]
    texts = {row["signedStatement"] for row in valve.team.net.rows(GRAPH, SWM, "CuratorStatement")
             if row["identifier"] in (IP, f"author:{valve.alice.author}")}
    assert len(texts) == 2 * len(rows) and len(rows) == 2                              # the copies ARE on the graph
    assert seen == rows                                                                # and read back as the statements they copy
    assert valve.pool().entries == before and valve.verify(valve.bundle()).ok


def test_the_pool_hands_on_the_statement_as_its_curators_wrote_it_whatever_copies_it_is_given():
    """The pure function, fed raw rows: a rewritten copy alone, and a copy an outsider added a
    signature to, read before or after the genuine one."""
    side = Side(GRAPH)                                                   # its rows are signed on 2026-10-02
    genuine = side.row(Kind.CONFIRMATION, IP, CITED)
    rewritten = {**genuine, "signedStatement": json.dumps(json.loads(genuine["signedStatement"]), indent=1)}
    for _ in range(4):                                                   # several outsider keys: some sort before the curators'
        outsider = Ed25519PrivateKey.generate()                          # gitleaks:allow — a throwaway test key
        padded = {**genuine, "signedStatement": signing.cosign(signing.from_text(genuine["signedStatement"]), outsider).to_text()}
        for rows in ([rewritten], [padded, genuine], [genuine, padded], [padded, rewritten]):
            entries = pool.confirmed_pool(side.manifest, rows, [], graph=GRAPH, today="2026-10-03")
            assert [entry.confirmation for entry in entries] == [genuine["signedStatement"]]
            assert len(entries[0].curators) == 2 and entries[0].reporters == 0 and entries[0].severity == ""


def test_what_the_verified_authority_already_lists_is_withheld_and_an_unreadable_graph_is_not_an_empty_pool(valve, tmp_path):
    class AlreadyVerified:
        def iter_rules(self):
            return [("ioc", {"identifier": IP, "source": "public"})]

    with valve.team.b:
        ctx = valve.ctx()
        listed = handoff.read_live_pool(type(ctx)(**{**ctx.__dict__, "compiled": AlreadyVerified()}))
        assert [entry.identifier for entry in listed.entries] == [PACKAGE] and listed.withheld == 1
        valve.team.b.node.offline = True
        unreadable = handoff.read_live_pool(valve.ctx())
        assert "could not be read" in unreadable.unavailable and unreadable.entries == ()
        with pytest.raises(verbs.VerbError, match="nothing exported"):
            handoff.export(valve.ctx(), str(tmp_path / "never.json"))
    assert not (tmp_path / "never.json").exists()


# ------------------------------------------------------------------ the bundle, checked by someone who trusts none of us


def test_a_bundle_built_on_one_machine_verifies_on_another_that_holds_only_the_root_key(valve):
    text = valve.bundle()
    report = valve.verify(text)
    assert report.error == "" and report.ok and [result.identifier for result in report.entries] == [PACKAGE, IP]
    assert report.passed == valve.pool().entries                         # the receiver derives exactly what the exporter saw
    assert (report.manifest.threshold, len(report.manifest.curator_keys)) == (2, 3)
    document = json.loads(text)
    assert (document["format"], document["version"], document["environment"], document["graph"]) == (
        "blackbox.confirmed-pool", 1, NETWORK, GRAPH)
    assert set(document["entries"][0]) == {"identifier", "threat", "evidence", "confirmation", "reports", "listings"}


def _flip(text: str) -> str:
    """*text* with one hex digit of its first signature changed to another VALUE (the signature is now wrong)."""
    at = text.index('"sig":"') + 12
    return text[:at] + ("0" if text[at] != "0" else "1") + text[at + 1:]


def _upper(text: str) -> str:
    """*text* with its first signature's hex in upper case: the SAME signature, written differently."""
    start = text.index('"sig":"') + 7
    assert text[start:start + 128] != text[start:start + 128].upper()
    return text[:start] + text[start:start + 128].upper() + text[start + 128:]


def _entry(document, identifier):
    return next(entry for entry in document["entries"] if entry["identifier"] == identifier)


TAMPERINGS = {
    "the stated evidence": (lambda e, d: e.update(evidence="advisory:MAL-0000-0000"), "evidence"),
    "the stated severity": (lambda e, d: e["threat"].update(severity="low"), "threat"),
    "a stated field": (lambda e, d: e["threat"]["fields"].update(ioc_type="domain"), "threat"),
    "an added stated field": (lambda e, d: e["threat"]["fields"].update(hostname="build-box"), "threat"),
    "the stated category": (lambda e, d: e["threat"].update(category="dependency"), "threat"),
    "one character of the confirmation's signature": (lambda e, d: e.update(confirmation=_flip(e["confirmation"])), "the confirmation does not verify"),
    "a space added inside the confirmation": (lambda e, d: e.update(confirmation=e["confirmation"].replace(",", ", ", 1)), "the confirmation does not verify"),
    "the confirmation's signature in upper-case hex": (lambda e, d: e.update(confirmation=_upper(e["confirmation"])), "the confirmation does not verify"),
    "a report's signature in upper-case hex": (lambda e, d: e["reports"].__setitem__(0, _upper(e["reports"][0])), "report 1 does not verify"),
    "the confirmation of another threat": (lambda e, d: e.update(confirmation=_entry(d, PACKAGE)["confirmation"]), "about another threat"),
    "a listing in place of the confirmation": (lambda e, d: e.update(confirmation=e["listings"][0]), "another kind of statement"),
    "one character of a report's signature": (lambda e, d: e["reports"].__setitem__(0, _flip(e["reports"][0])), "report 1 does not verify"),
    "a space added inside a report": (lambda e, d: e["reports"].__setitem__(1, e["reports"][1].replace(":", ": ", 1)), "report 2 does not verify"),
    "a report about another threat": (lambda e, d: e["reports"].append(_entry(d, PACKAGE)["reports"][0]), "is about another threat"),
    "the same report twice": (lambda e, d: e["reports"].append(e["reports"][0]), "reports"),
    "the reports in another order": (lambda e, d: e["reports"].reverse(), "reports"),
    "one character of a listing's signature": (lambda e, d: e["listings"].__setitem__(0, _flip(e["listings"][0])), "listing 1 does not verify"),
    "a confirmation in place of a listing": (lambda e, d: e["listings"].append(e["confirmation"]), "another kind of statement"),
    "an extra key": (lambda e, d: e.update(note="trust me"), "malformed"),
    "a missing key": (lambda e, d: e.pop("listings"), "malformed"),
}


@pytest.mark.parametrize("what", sorted(TAMPERINGS))
def test_changing_an_entry_makes_that_entry_fail_by_name_and_the_others_still_pass(valve, what):
    change, expected = TAMPERINGS[what]
    document = json.loads(valve.bundle())
    change(_entry(document, IP), copy.deepcopy(document))
    report = valve.verify(json.dumps(document))
    results = {result.identifier: result for result in report.entries}
    assert report.error == "" and not report.ok
    assert not results[IP].ok and expected in results[IP].reason, results[IP].reason
    assert results[PACKAGE].ok and [entry.identifier for entry in report.passed] == [PACKAGE]


def test_a_listing_of_someone_who_did_not_report_the_threat_fails_the_entry(valve):
    carol = Reporter("0xc")
    valve.team.two_key(Kind.COUNTED_AUTHORS, f"author:{carol.author}", _listing(carol))
    with valve.team.b:
        rows = community.known_curator_statements(valve.team.b.node, CFG, [f"author:{carol.author}"])
    document = json.loads(valve.bundle())
    _entry(document, IP)["listings"].append(rows[0][1]["signedStatement"])
    _entry(document, IP)["listings"].sort()
    result = {r.identifier: r for r in valve.verify(json.dumps(document)).entries}[IP]
    assert not result.ok and "listings" in result.reason


def test_a_second_entry_for_the_same_threat_fails(valve):
    document = json.loads(valve.bundle())
    document["entries"].append(copy.deepcopy(_entry(document, IP)))
    results = valve.verify(json.dumps(document)).entries
    assert [r.ok for r in results] == [True, True, False] and "second entry" in results[2].reason


@pytest.mark.parametrize("what, expected", [
    ("another network", "another network or another graph"),
    ("another graph", "another network or another graph"),
    ("a header edited to match", "no key manifest in the bundle is signed by the given root"),
    ("another root", "no key manifest in the bundle is signed by the given root"),
    ("no root", "no root key was given"),
    ("a newer version", "is not supported"),
    ("a version that is not a number", "is not supported"),
    ("not json", "not valid JSON"),
    ("another format", "not a confirmed-pool bundle"),
    ("entries that are not a list", "malformed"),
    ("a manifest that is not text", "malformed"),
])
def test_a_bundle_fails_as_a_whole(valve, what, expected):
    text = valve.bundle()
    document = json.loads(text)
    over = {}
    if what == "another network":
        over["environment"] = "another-network"
    elif what == "another graph":
        over["graph"] = "0xabc/another-graph"
    elif what == "a header edited to match":             # a bundle of THIS network presented as another's
        document["environment"] = over["environment"] = "another-network"
    elif what == "another root":
        over["roots"] = {"ab" * 32}
    elif what == "no root":
        over["roots"] = set()
    elif what == "a newer version":
        document["version"] = 2
    elif what == "a version that is not a number":
        document["version"] = True
    elif what == "another format":
        document["format"] = "something-else"
    elif what == "entries that are not a list":
        document["entries"] = {"0": document["entries"][0]}
    elif what == "a manifest that is not text":
        document["manifests"] = [{"signedStatement": document["manifests"][0]}]
    report = valve.verify("{not json" if what == "not json" else json.dumps(document), **over)
    assert expected in report.error and report.entries == () and not report.ok and report.passed == ()


def test_an_old_bundle_reports_expired_entries_and_keeps_the_rest(valve):
    later = (utc_today() + timedelta(days=60)).isoformat()                  # past an IP's 47 days, inside a package's 460
    results = {r.identifier: r for r in valve.verify(valve.bundle(), today=later).entries}
    assert results[PACKAGE].ok and not results[IP].ok and "expired" in results[IP].reason


def test_a_signed_text_on_its_own_is_checked_like_a_row_that_was_read(valve):
    entry = _entry(json.loads(valve.bundle()), IP)
    verifier = community.ReportVerifier(NETWORK, GRAPH)
    assert verifier.verify_signed(entry["reports"][0]).identifier == IP
    assert verifier.verify_signed(_flip(entry["reports"][0])) is None and verifier.verify_signed("not a statement") is None
    assert verifier.verify_signed(_upper(entry["reports"][0])).identifier == IP        # a reader accepts it; a bundle does not
    assert community.ReportVerifier("another-network", GRAPH).verify_signed(entry["reports"][0]) is None
    assert cs.row_for_signed(entry["confirmation"])["identifier"] == IP
    assert cs.row_for_signed(entry["confirmation"] + " ") is None and cs.row_for_signed(entry["reports"][0]) is None


def _by_hand(side, entries):
    """A bundle document for *side* written by hand (what a hostile sender could assemble)."""
    return {"format": "blackbox.confirmed-pool", "version": 1, "environment": NETWORK, "graph": GRAPH,
            "manifests": [side.manifest_row()["signedStatement"]], "entries": entries}


def test_a_genuinely_signed_confirmation_without_evidence_is_not_a_pool_entry():
    side = Side(GRAPH)
    bare = side.row(Kind.CONFIRMATION, IP, {})["signedStatement"]                    # two real curator signatures, no evidence
    entry = {"identifier": IP, "threat": {"category": "ioc", "severity": "", "fields": {}}, "evidence": "",
             "confirmation": bare, "reports": [], "listings": []}
    report = pool.verify_bundle(json.dumps(_by_hand(side, [entry])), {side.root_hex}, environment=NETWORK, graph=GRAPH,
                                today="2026-10-03")
    assert report.error == "" and not report.entries[0].ok and "no evidence reference" in report.entries[0].reason


def test_two_root_signed_manifests_that_disagree_fail_the_whole_bundle():
    side = Side(GRAPH)
    other = dataclasses.replace(side.manifest, curator_keys=tuple(sorted(
        signing.public_key_hex(Ed25519PrivateKey.generate()) for _ in range(3))))    # gitleaks:allow — throwaway test keys
    document = _by_hand(side, [])
    document["manifests"].append(signing_manifest(other, side.root))
    report = pool.verify_bundle(json.dumps(document), {side.root_hex}, environment=NETWORK, graph=GRAPH, today="2026-10-03")
    assert "disagree" in report.error and not report.ok


def test_a_threat_the_verified_authority_rejected_is_not_in_the_pool(monkeypatch, tmp_path):
    """The most restrictive word wins: the community curators confirmed it, the verified authority rejected it."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "home"))
    ours, theirs = Side(GRAPH), Side(AUTHORITY_CFG.context_graph_id)
    monkeypatch.setenv("BLACKBOX_COMMUNITY_ROOT_KEYS", ours.root_hex)
    monkeypatch.setenv("BLACKBOX_CURATOR_ROOT_KEYS", theirs.root_hex)
    alice = Reporter("0xa")
    other = "ioc:ip:203.0.113.8"
    node = Store(verified=[theirs.manifest_row()], reports=[signed_row(IP, alice), signed_row(other, alice)],
                 community=[ours.manifest_row(), ours.row(Kind.CONFIRMATION, IP, CITED), ours.row(Kind.CONFIRMATION, other, CITED),
                            theirs.row(Kind.REJECTION, IP, {"reason": "benign"}, graph=GRAPH)])
    view = community.read_curator_view(node, AUTHORITY_CFG, interest=[IP, other])
    ctx = CurateContext(cfg=AUTHORITY_CFG, client=node, environment=NETWORK, view=view, sandbox=True, compiled=None,
                        authority=Authority.COMMUNITY)
    found = handoff.read_live_pool(ctx)
    assert [entry.identifier for entry in found.entries] == [other] and found.withheld == 1


# ------------------------------------------------------------------ the commands and the receiver's dossier


def test_export_writes_the_bundle_and_verify_bundle_checks_it_offline(valve, tmp_path, capsys):
    out = tmp_path / "handoff" / "pool.json"
    with valve.team.b:
        assert handoff.export(valve.ctx(), str(out)) == 0 and handoff.print_pool(valve.ctx()) == 0
    assert "exported 2 confirmed threat(s)" in capsys.readouterr().out and list(out.parent.iterdir()) == [out]
    valve.receiver.node.offline = True                                       # the receiver's node is not needed at all
    with valve.receiver:
        before = len(valve.receiver.node.queries)
        assert handoff.verify_file(str(out), root=valve.root, network=NETWORK, graph=GRAPH) == 0
        assert "2 of 2 entries verified" in capsys.readouterr().out and len(valve.receiver.node.queries) == before
        document = json.loads(out.read_text(encoding="utf-8"))
        _entry(document, IP)["evidence"] = "advisory:MAL-0000-0000"
        out.write_text(json.dumps(document), encoding="utf-8")
        assert handoff.verify_file(str(out), root=valve.root, network=NETWORK, graph=GRAPH) == 2
        printed = capsys.readouterr().out
        assert "1 of 2 entries verified" in printed and f"FAILED  {IP}" in printed
        assert handoff.verify_file(str(out), root="ab" * 32, network=NETWORK, graph=GRAPH) == 2
        assert "BUNDLE REFUSED" in capsys.readouterr().out
        with pytest.raises(verbs.VerbError, match="cannot read the bundle"):
            handoff.verify_file(str(tmp_path / "missing.json"), root=valve.root, network=NETWORK, graph=GRAPH)


def test_the_stand_in_verified_authoritys_dossier_shows_the_confirmation_and_its_evidence(valve, tmp_path):
    out = tmp_path / "pool.json"
    with valve.team.b:
        handoff.export(valve.ctx(), str(out))
    with valve.receiver:                                                     # a curator of ANOTHER authority
        ctx = valve.team.ctx(valve.receiver, authority=Authority.VERIFIED)
        from_bundle = handoff.confirmation_for(ctx, IP, str(out))
        assert (from_bundle.evidence, from_bundle.curators, from_bundle.reporters) == (EVIDENCE, 2, 2)
        assert handoff.confirmation_for(ctx, "ioc:ip:203.0.113.99", str(out)) is None
        live = handoff.confirmation_for(valve.team.ctx(valve.receiver, interest=[IP], authority=Authority.VERIFIED), IP)
        assert (live.evidence, live.curators, live.source) == (EVIDENCE, 2, "the community graph")
    valve.team.two_key(Kind.REJECTION, PACKAGE, {"reason": "benign"})        # a verdict that is NOT a confirmation
    with valve.receiver:
        assert handoff.confirmation_for(valve.team.ctx(valve.receiver, interest=[PACKAGE], authority=Authority.VERIFIED), PACKAGE) is None
        assert handoff.confirmation_for(valve.team.ctx(valve.receiver, interest=[IP], authority=Authority.VERIFIED), IP) is not None
        document = json.loads(out.read_text(encoding="utf-8"))
        out.write_text(json.dumps({**document, "graph": "0xabc/another-graph"}), encoding="utf-8")
        with pytest.raises(verbs.VerbError, match="the bundle was refused"):
            handoff.confirmation_for(ctx, IP, str(out))
    lines = dossier.render(dossier.DossierBuilder(IP).community_confirmation(from_bundle).community_confirmation(None).build())
    assert EVIDENCE in lines[1] and "a verified export bundle" in lines[1] and "check it yourself" in lines[1]
    assert "no confirmation with evidence" in lines[2]


def test_the_saved_view_lists_exactly_the_confirmation_statements():
    view = node_ui_views.find_view("confirmed-pool")
    assert view in node_ui_views.COMMUNITY_VIEWS
    assert cs.statement_subject(Kind.CONFIRMATION, IP, 1).startswith("urn:guardian:curator:confirmation:")
    assert 'STRSTARTS(STR(?r), "urn:guardian:curator:confirmation:")' in view.sparql and "?signedStatement" in view.sparql
