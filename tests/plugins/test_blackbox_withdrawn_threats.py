"""KI-275 — a threat that was rejected, revoked or retracted is never kept on a reader.

Readers keep a counted threat whose network copies expired for up to 90 days
(R5), and keep their last good tier through an empty read they do not believe
yet (KI-262) or a pause. A rejection or a retraction also makes a threat
vanish from the read — on purpose. Before this fix both safety nets brought
the threat back at its old FLAG, so a curator rejection did not reach the hot
path for up to 90 days. Reductions always get through (LES-016).
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from _clock import utc_today
from _community_rows import GRAPH, NETWORK, Reporter
from _machines import SWM, share_report
from test_blackbox_curate_community import CFG, Curators, _listing

from plugins.blackbox.community import CommunityRead, ReadState, report_builder
from plugins.blackbox.community.report_signer import ReportSigner
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.community.statements.curator_statements import CuratorRecord
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind
from plugins.blackbox.ruleset import community_tier, compiler

X, Y = "ioc:ip:203.0.113.7", "ioc:ip:203.0.113.8"


@pytest.fixture(autouse=True)
def no_join(monkeypatch):
    monkeypatch.setattr(community_tier.community, "ensure_community_subscription", lambda client, cfg: None)


class Reader(Curators):
    """The curators, a listed reporter F, and a reader that keeps its own tier history."""

    def __init__(self, tmp_path, monkeypatch):
        super().__init__(tmp_path, monkeypatch)
        self.f = Reporter("0xf")
        self.two_key(Kind.COUNTED_AUTHORS, f"author:{self.f.author}", _listing(self.f))
        self.tier = None

    def compile(self):
        with self.reader:
            tier = compiler.Ruleset()
            community_tier.apply_community_tier(tier, self.reader.node, CFG, self.tier)
        self.tier = tier
        return tier

    def report(self, identifier):
        share_report(self.reader.node, identifier, self.f)

    def retract(self, identifier):
        signer = ReportSigner(private_key=self.f.key, environment=NETWORK, graph=GRAPH)
        self.net.put(GRAPH, SWM, "F", f"retract-{identifier}",
                     report_builder.build_retraction_quads(identifier=identifier, reporter_address=self.f.address, signer=signer))

    def expire(self, identifier):
        """Shared memory forgot this threat's report (no statement says anything about it)."""
        store = self.net.assets[(GRAPH, SWM)]
        def is_its_report(quads):
            return (any(q["object"].rstrip(">").endswith("ThreatReport") for q in quads)
                    and any(identifier in q["object"] for q in quads))
        for key in [key for key, quads in store.items() if is_its_report(quads)]:
            del store[key]

    def matchable(self, identifier):
        return identifier in self.tier.ioc


@pytest.fixture
def team(tmp_path, monkeypatch):
    return Reader(tmp_path, monkeypatch)


def test_a_rejected_threat_is_gone_at_once_while_others_stay(team):
    team.report(X), team.report(Y)
    assert team.compile() and team.matchable(X) and team.matchable(Y)
    team.two_key(Kind.REJECTION, X, {"reason": "benign"})
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)
    team.compile()                                                           # and on every later read
    assert X not in team.tier.community


def test_a_retracted_threat_is_not_kept_locally(team):
    team.report(X), team.report(Y)
    team.compile()
    team.retract(X)
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)


def test_when_every_missing_threat_was_withdrawn_nothing_is_kept(team):
    team.report(X)
    team.compile()
    team.two_key(Kind.REJECTION, X, {"reason": "benign"})
    tier = team.compile()
    assert tier.community == {} and not team.matchable(X)


def test_a_rejection_published_after_the_reports_expired_is_still_seen(team):
    """The reader asks the curators about every threat it holds, not only those still reported."""
    team.report(X), team.report(Y)
    team.compile()
    team.two_key(Kind.REJECTION, X, {"reason": "benign"})
    team.expire(X)                                                           # X's report is gone; Y's is still there
    team.compile()
    assert X not in team.tier.community and not team.matchable(X) and team.matchable(Y)


def test_an_empty_read_keeps_what_it_cannot_explain_and_drops_what_it_can(team):
    team.report(X), team.report(Y)
    team.compile()
    team.expire(Y)                                                           # Y vanished for no stated reason
    team.two_key(Kind.REJECTION, X, {"reason": "benign"})                    # X was rejected
    team.expire(X)                                                           # and its report is gone too: the read is empty
    team.compile()
    assert X not in team.tier.community and not team.matchable(X)
    assert team.matchable(Y) and Y in team.tier.community                    # a busy store must not wipe Y (KI-262)


def test_a_threat_that_merely_expired_is_still_kept_locally(team):
    team.report(X), team.report(Y)
    team.compile()
    team.expire(X)
    team.compile()
    assert team.tier.community[X]["networkLive"] == "no" and team.matchable(X)


def test_a_rejection_gets_through_while_intake_is_paused(team):
    team.report(X), team.report(Y)
    team.compile()
    until = (utc_today() + timedelta(days=3)).isoformat()
    team.two_key(Kind.PAUSE, "curator", {"until": until})
    team.two_key(Kind.REJECTION, X, {"reason": "benign"}, first=team.c, second=team.a)
    tier = team.compile()
    assert tier.community_paused and X not in tier.community and not team.matchable(X) and team.matchable(Y)


def test_a_revocation_counts_as_withdrawn():
    revoked = CuratorRecord(kind=Kind.REVOCATION, identifier=X, sequence=2, day="2026-10-03",
                            fields=(("reason", "false-positive"),), signers=frozenset({"a" * 64, "b" * 64}))
    rejected = CuratorRecord(kind=Kind.REJECTION, identifier=Y, sequence=2, day="2026-10-03",
                             fields=(("reason", "benign"),), signers=frozenset({"a" * 64, "b" * 64}))
    read = CommunityRead(ReadState.ROWS, curator=cv.CuratorView(verdicts={X: revoked, Y: rejected}))
    assert community_tier._withdrawn(read) == {X, Y}
