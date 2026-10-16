"""Community Curation C5 — keeping the authority's word alive.

Shared memory forgets after about 30 days. The machine that published a
statement re-publishes it once per keep-alive epoch, so a reader that joins
later still finds it; only CURRENT statements are kept alive; and a heartbeat
lets readers tell a silent curator from an absent one.

Curators and a reader run as separate machines over one shared in-memory
network; "the network forgot" is ``net.forget(GRAPH)``.
"""

from __future__ import annotations

import dataclasses
import time
from datetime import date, timedelta

import pytest
from _clock import utc_today
from _community_rows import GRAPH, Reporter
from _machines import SWM, Machine
from test_blackbox_curate_community import CFG, THREAT, Curators, _listing

from plugins.blackbox.community import read_curator_view
from plugins.blackbox.community.statements import curator_statements as cs
from plugins.blackbox.community.statements import curator_view as cv
from plugins.blackbox.curate import keys, verbs
from plugins.blackbox.curate.proposal import ProposalStore
from plugins.blackbox.curate.upkeep import heartbeat, published
from plugins.blackbox.kernel import signing
from plugins.blackbox.kernel.signing.authority import Authority
from plugins.blackbox.kernel.signing.statement_order import CuratorStatement as Kind

DAY = 86_400.0
EPOCH = 10 * DAY           # the default keep-alive epoch
NOW = time.time()          # statements are signed on the real clock; the tests move forward from it


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("BLACKBOX_CURATOR_ROOT_KEYS", raising=False)
    monkeypatch.delenv("BLACKBOX_COMMUNITY_ROOT_KEYS", raising=False)


def _fresh_reader(team, tmp_path, monkeypatch, name="NEW"):
    """A machine that has never read the graph: it knows only what the network holds NOW."""
    return Machine(team.net, tmp_path, monkeypatch, name)


def _counted(machine, reporter):
    with machine:
        return reporter.author in read_curator_view(machine.node, CFG, interest=[f"author:{reporter.author}"]).counted


def _keep_alive(team, machine, now):
    with machine:
        return published.publish_due(machine.node, CFG, now=now)


# ------------------------------------------------------------------ what a late joiner finds


def test_a_rejection_is_still_honoured_by_a_fresh_reader_after_the_first_copy_expired(tmp_path, monkeypatch):
    """The item's done-when (KI-251): rejected reports must not count again when the network forgets."""
    team = Curators(tmp_path, monkeypatch)
    team.two_key(Kind.REJECTION, THREAT, {"reason": "benign"})
    team.net.forget(GRAPH)                                              # shared memory expired everything
    late = _fresh_reader(team, tmp_path, monkeypatch)
    with late:
        assert not read_curator_view(late.node, CFG, interest=[THREAT]).rejected(THREAT)   # nothing on the network: unknown
    assert _keep_alive(team, team.a, NOW + EPOCH) >= 1                  # A published the manifest
    assert _keep_alive(team, team.b, NOW + EPOCH) == 1                  # B published the rejection
    with late:
        assert read_curator_view(late.node, CFG, interest=[THREAT]).rejected(THREAT)


def test_the_manifest_and_a_listing_come_back_and_each_counts_once(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    _keep_alive(team, team.a, NOW + EPOCH)
    _keep_alive(team, team.b, NOW + EPOCH)                              # copies sit BESIDE the originals
    names = sorted(name for (_, name) in team.net.assets[(GRAPH, SWM)])
    assert sum(name.startswith("key-manifest-1-1") for name in names) == 2
    assert _counted(team.reader, alice)
    with team.reader:
        from plugins.blackbox.community.trust import trust_store
        assert len(trust_store.TrustStore().load(GRAPH).statements) == 1   # two network copies, one statement


def test_one_copy_per_epoch_and_none_when_keep_alive_is_off(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    window = (int(NOW // EPOCH) + 1) * EPOCH                             # the start of the next keep-alive window
    assert _keep_alive(team, team.b, window + DAY) == 1
    assert _keep_alive(team, team.b, window + 2 * DAY) == 0              # same window: nothing to do
    assert _keep_alive(team, team.b, window + EPOCH + DAY) == 1          # the window after
    off = dataclasses.replace(CFG, community_keepalive_epoch_days=0)
    with team.b:
        assert published.publish_due(team.b.node, off, now=NOW + 5 * EPOCH) == 0


# ------------------------------------------------------------------ only current statements


def test_a_superseded_listing_lapses_and_its_delisting_is_kept_alive(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    identifier = f"author:{alice.author}"
    team.two_key(Kind.COUNTED_AUTHORS, identifier, _listing(alice))
    team.two_key(Kind.COUNTED_AUTHORS, identifier, _listing(alice, listed="no"))
    with team.b:
        kept = published.store().all()
        assert len(kept) == 1 and '\\"listed\\":\\"no\\"' in "".join(q["object"] for q in kept[0].quads)
    team.net.forget(GRAPH)
    _keep_alive(team, team.a, NOW + EPOCH)
    _keep_alive(team, team.b, NOW + EPOCH)
    late = _fresh_reader(team, tmp_path, monkeypatch)
    with late:
        view = read_curator_view(late.node, CFG, interest=[identifier])
    assert alice.author not in view.counted and alice.author in view.delisted


def test_a_rejection_supersedes_the_confirmation_it_follows(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    team.two_key(Kind.CONFIRMATION, THREAT, {})
    team.two_key(Kind.REJECTION, THREAT, {"reason": "benign"})
    with team.b:
        envelopes = [published._signed(entry.quads).statement_type for entry in published.store().all()]
    assert envelopes == [Kind.REJECTION.value]


def test_a_listing_past_the_day_readers_stop_counting_it_is_retired(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    far = (utc_today() + timedelta(days=300)).isoformat()             # the listing states 300 days; readers count 90
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice, expires=far))
    assert _keep_alive(team, team.b, NOW + (cv.COMMUNITY_LISTING_MAX_DAYS - 20) * DAY) == 1   # still counted: kept alive
    assert _keep_alive(team, team.b, NOW + (cv.COMMUNITY_LISTING_MAX_DAYS + 2) * DAY) == 0
    with team.b:
        assert published.store().all() == []


def test_a_reporters_erasure_stops_keep_alive_of_its_listing(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    alice, bob = Reporter("0xa"), Reporter("0xb")
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{bob.author}", _listing(bob))
    with team.b:
        assert published.forget_identifier(f"author:{alice.author}") == 1
        assert [entry.identifier for entry in published.store().all()] == [f"author:{bob.author}"]


def test_a_refused_copy_ends_the_beat_and_is_sent_on_the_next(tmp_path, monkeypatch):
    """The fail-open path, run for real."""
    team = Curators(tmp_path, monkeypatch)
    alice = Reporter("0xa")
    team.two_key(Kind.COUNTED_AUTHORS, f"author:{alice.author}", _listing(alice))
    team.b.node.refuse_shares = True
    assert _keep_alive(team, team.b, NOW + EPOCH) == 0
    team.b.node.refuse_shares = False
    assert _keep_alive(team, team.b, NOW + EPOCH) == 1


# ------------------------------------------------------------------ heartbeats


def test_a_heartbeat_is_published_by_one_key_and_seen_by_a_reader(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    with team.a:
        _, outcome = heartbeat.publish_heartbeat(team.ctx(team.a, interest=["curator"]), ProposalStore(), yes=True)
        assert outcome.startswith("published")
        assert published.store().all()[0].name.startswith("key-manifest")          # the heartbeat itself is not kept alive
        assert len(published.store().all()) == 1
    with team.reader:
        beats = read_curator_view(team.reader.node, CFG).community.heartbeats
    assert set(beats) == {team.keys["A"]}


def test_a_machine_whose_key_is_not_a_curator_key_cannot_beat(tmp_path, monkeypatch):
    team = Curators(tmp_path, monkeypatch)
    with team.reader:
        with pytest.raises(verbs.VerbError, match="not a curator key"):
            heartbeat.publish_heartbeat(team.ctx(team.reader), ProposalStore(), yes=True)


def test_the_root_alone_may_lower_only_after_the_curators_have_been_silent_for_a_week(tmp_path, monkeypatch):
    """KI-247: with a heartbeat ever seen, silence is measurable — and only then may the root act alone."""
    team = Curators(tmp_path, monkeypatch)
    with team.a:
        ctx = team.ctx(team.a, interest=["curator"])
        heartbeat.publish_heartbeat(ctx, ProposalStore(), yes=True)
        beat_day = read_curator_view(team.a.node, CFG).community.heartbeats[team.keys["A"]]
        root = keys.root_key_store(Authority.COMMUNITY).load_or_create()
        alone = cs.sign_statement(Kind.REJECTION, THREAT, sequence=1, fields={"reason": "benign"}, key=root,
                                  manifest=ctx.manifest, graph=GRAPH)
        assert signing.public_key_hex(root) not in ctx.manifest.curator_keys
        team.a.node.share_knowledge_asset(GRAPH, "root-alone-rejection", cs.statement_quads(alone))
    def on(days):
        day = (date.fromisoformat(beat_day) + timedelta(days=days)).isoformat()
        monkeypatch.setattr(cv, "_today", lambda: day)
        with _fresh_reader(team, tmp_path, monkeypatch, f"R{days}") as reader:
            return read_curator_view(reader.node, CFG, interest=[THREAT]).rejected(THREAT)
    assert not on(3)                                                   # the curators beat three days ago: the root alone counts for nothing
    assert on(8)                                                       # silent for more than seven days: its reduction is honoured
