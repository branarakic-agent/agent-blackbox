"""Community Curation C12 — the whole flow, as several machines, on every run of the suite.

Plan section 14, layer 2. One shared in-memory network (``_machines``) holds:
reporter nodes (F, and a second partner P), three community curators (A, B, C)
each running the curator service with its OWN advisory lookup, a plain reader
(R) and a receiver (U) that holds nothing but the community root key. Every
step's effect is observed on a machine other than the one that acted.

    root signs the manifest ............. R trusts the three curator keys
    F and P are granted PARTNER (2 keys)  their reports count on R
    F reports a package and an address .. both FLAG on R
    A and B each find the advisory ...... the package is CONFIRMED on R, no command typed
    the confirmation credits F .......... in B's private ledger
    B exports the pool .................. U verifies it offline and sees it in its dossier
    P disputes the address .............. the address decays to MONITOR on R
    F retracts the address .............. F's voice is withdrawn on R
    two curators reject the package ..... REJECTED on R, and it leaves the pool
    two curators delist F ............... F's next report only MONITORs on R
    two curators pause intake ........... R keeps its last good tier, paused
    the curators fall silent ............ R's operator sees it, flags in force stay
    an address outlives its lifetime .... EXPIRED on R
"""

from __future__ import annotations

import dataclasses
import json
import time
from datetime import timedelta

import pytest
from _clock import utc_today
from _community_rows import GRAPH, NETWORK, Reporter
from _machines import Machine, share_report
from test_blackbox_curate_community import CFG, _listing
from test_blackbox_curator_service import FOUND, Service

from plugins.blackbox import community
from plugins.blackbox.community import pool, report_builder
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.curate import handoff, keys
from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.signing.authority import Authority
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

PKG = "dep:npm:evil-pkg@1.0.0"
ADDR = "ioc:ip:203.0.113.7"
LATER = "ioc:ip:203.0.113.99"
DAY = 86_400


class Flow(Service):
    """The service harness plus a second partner, a reader view and a receiver."""

    def __init__(self, tmp_path, monkeypatch):
        super().__init__(tmp_path, monkeypatch)
        self.f, self.p = Reporter("0xf"), Reporter("0xp")
        self.receiver = Machine(self.team.net, tmp_path, monkeypatch, "U")
        with self.team.a:
            self.root = keys.root_key_store(Authority.COMMUNITY).public_key_hex()
        self.tier = None                                       # the reader's last compiled tier

    def partner(self, reporter, org):
        self.team.two_key(Kind.COUNTED_AUTHORS, f"author:{reporter.author}", _listing(reporter, **{"class": "partner", "org": org}))

    def statement(self, quads, name):
        self.team.net.put(GRAPH, "shared-working-memory", "F", name, quads)

    def signer(self, reporter):
        return ReportSigner(private_key=reporter.key, environment=NETWORK, graph=GRAPH)

    def on_reader(self, now=None):
        """The reader compiles its community tier (its previous one is its history)."""
        if now is not None:
            community_tier.time.time = lambda: now
        with self.team.reader:
            tier = compiler.Ruleset()
            community_tier.apply_community_tier(tier, self.team.reader.node, CFG, self.tier)
        self.tier = tier
        return tier

    def stage(self, identifier):
        rule = self.tier.community.get(identifier) or {}
        return rule.get("stage"), rule.get("enforcement")


@pytest.fixture
def flow(tmp_path, monkeypatch):
    monkeypatch.setattr(community_tier.time, "time", time.time)        # restored after the test (on_reader moves the clock)
    return Flow(tmp_path, monkeypatch)


def test_the_full_flow_from_report_to_hand_off_and_back_down(flow, tmp_path):
    # --- trust: the manifest is in place (the harness published it); two partners are listed by two keys
    flow.partner(flow.f, "acme")
    flow.partner(flow.p, "beta-labs")
    with flow.team.reader:
        view = community.read_curator_view(flow.team.reader.node, CFG, interest=[f"author:{flow.f.author}", f"author:{flow.p.author}"])
    assert view.community.manifest.threshold == 2 and {flow.f.author, flow.p.author} <= set(view.counted)

    # --- F reports a package and an address: both FLAG on the reader
    share_report(flow.team.reader.node, PKG, flow.f)
    share_report(flow.team.reader.node, ADDR, flow.f)
    flow.on_reader()
    assert flow.stage(PKG) == ("reported", "flag") and flow.stage(ADDR) == ("reported", "flag")

    # --- the curator service: A and B each find the advisory themselves; no command is typed
    flow.answers[PKG] = FOUND
    first, second = flow.beat("A"), flow.beat("B")
    assert len(first.proposed) == 1 and len(second.cosigned) == 1 and first.errors == second.errors == ()
    flow.on_reader()
    assert flow.stage(PKG) == ("corroborated", "flag") and "confirmed by the curator" in flow.tier.community[PKG]["stageReason"]

    # --- the confirmation credited F in B's private ledger (B published it)
    with flow.team.b:
        assert community.reputation.ReputationLedger().standing(flow.f.author).confirmed == 1

    # --- B exports the pool; U, holding only the root key, verifies it offline and sees it in its dossier
    bundle = tmp_path / "handoff.json"
    with flow.team.b:
        handoff.export(flow.ctx(flow.team.b, [PKG, ADDR]), str(bundle))
    with flow.receiver:
        report = pool.verify_bundle(bundle.read_text(encoding="utf-8"), {flow.root}, environment=NETWORK, graph=GRAPH)
        assert report.ok and [entry.identifier for entry in report.passed] == [PKG]
        confirmed = handoff.confirmation_for(flow.team.ctx(flow.receiver, authority=Authority.VERIFIED), PKG, str(bundle))
        assert confirmed.evidence == "advisory:MAL-2026-1" and confirmed.reporters == 1

    # --- P, a counted partner, disputes the address: it decays to MONITOR on the reader
    flow.statement(report_builder.build_false_positive_quads(identifier=ADDR, reporter_address=flow.p.address, reason="wrong",
                                                             signer=flow.signer(flow.p)), "dispute-p")
    flow.on_reader()
    assert flow.stage(ADDR) == ("reported", "monitor") and flow.tier.community[ADDR]["disputed"] == "yes"

    # --- F retracts the address: its voice is withdrawn on the reader
    flow.statement(report_builder.build_retraction_quads(identifier=ADDR, reporter_address=flow.f.address,
                                                         signer=flow.signer(flow.f)), "retract-f")
    flow.on_reader()
    assert ADDR not in flow.tier.community and ADDR not in flow.tier.ioc         # withdrawn, and NOT kept locally (KI-275)

    # --- two curators reject the package: REJECTED on the reader, and it leaves the pool
    flow.team.two_key(Kind.REJECTION, PKG, {"reason": "benign"}, first=flow.team.c, second=flow.team.a)
    flow.on_reader()
    assert PKG not in flow.tier.community and PKG not in flow.tier.dependency    # gone, and NOT kept locally (KI-275)
    with flow.team.b:
        assert handoff.read_live_pool(flow.ctx(flow.team.b, [PKG, ADDR])).entries == ()

    # --- two curators delist F: F's next report only MONITORs on the reader
    flow.team.two_key(Kind.COUNTED_AUTHORS, f"author:{flow.f.author}", _listing(flow.f, listed="no", **{"class": "partner", "org": "acme"}),
                      first=flow.team.b, second=flow.team.c)
    share_report(flow.team.reader.node, LATER, flow.f)
    flow.on_reader()
    assert flow.stage(LATER) == ("reported", "monitor")

    # --- the curators fall silent: three days on, the reader's operator is told; flags in force stay
    three_days = (utc_today() + timedelta(days=3)).isoformat()
    with flow.team.reader:
        ours = community.read_verified_reports(flow.team.reader.node, CFG).curator.community
    silent = health.community_authority.gather(ours, three_days)
    assert silent.trusted and silent.silent_keys == silent.keys == 3
    assert any("community curators are silent" in message for _, message, _ in health.community_authority.alarms(silent))

    # --- an address outlives its 47-day lifetime: EXPIRED on the reader (the tier's own clock)
    flow.on_reader(now=time.time() + 48 * DAY)
    assert flow.stage(LATER) == ("expired", "monitor")

    # --- two curators pause intake: the reader keeps its last good tier and says it is paused
    flow.on_reader(now=time.time())
    before = dict(flow.tier.community)
    flow.team.two_key(Kind.PAUSE, "curator", {"until": three_days}, first=flow.team.a, second=flow.team.b)
    share_report(flow.team.reader.node, "ioc:ip:203.0.113.150", flow.p)
    paused = flow.on_reader()
    assert paused.community_paused and "ioc:ip:203.0.113.150" not in paused.community and set(paused.community) == set(before)
    assert json.dumps(dataclasses.asdict(silent))                       # (the inputs serialize: the dashboard serves them)
