"""The first sync says what it is doing, and only a stuck one raises the alarm (2026-10-22).

Founder, on a fresh node: a red "UNPROTECTED … run blackbox sync --wait" over a sync that
was already running, and a card at 0 / 565 with nothing moving, read as broken. The meter
now names the step (:func:`sync_phase`), :class:`SyncProgressWatch` tells "moving" from
"stalled", and the empty-ruleset health item is INFO while the first sync moves.
"""

from __future__ import annotations

import dataclasses

import pytest

from plugins.blackbox.dashboard import sync_meter
from plugins.blackbox.dashboard.sync_meter import STALL_SECONDS, SyncMeter, SyncProgressWatch, sync_phase
from plugins.blackbox.kernel import health
from plugins.blackbox.kernel.health.inputs import HealthInputs


def _meter(state="syncing", graph=565, downloaded=0, compiled=None):
    return SyncMeter(state=state, graph_assets=graph, downloaded_assets=downloaded, downloaded_triples=0,
                     compiled_assets=compiled, verified_rules=0, percent_downloaded=0.0, percent_compiled=0.0,
                     checked_at="")


@pytest.mark.parametrize(("meter", "stalled", "phase"), [
    (_meter(graph=None), False, "finding"),
    (_meter(downloaded=0), False, "queued"),
    (_meter(downloaded=120), False, "downloading"),
    (_meter(downloaded=565, compiled=300), False, "compiling"),
    (_meter(state="synced", downloaded=565, compiled=565), False, "synced"),
    (_meter(state="unavailable", downloaded=None), False, ""),
    (_meter(downloaded=120), True, "stalled"),
])
def test_the_phase_names_the_step(meter, stalled, phase):
    assert sync_phase(meter, stalled)[0] == phase


def test_the_queued_step_says_it_can_take_minutes():
    text = sync_phase(_meter(downloaded=0), False)[1]
    assert "565" in text and "several minutes" in text


class _Clock:
    def __init__(self):
        self.now = 1_000.0

    def __call__(self):
        return self.now


def test_a_sync_whose_counts_move_is_running_and_one_that_stops_moving_is_stalled():
    clock = _Clock()
    watch = SyncProgressWatch(clock=clock)
    first = watch.observe(_meter(downloaded=0))
    assert (first.running_since, first.stalled, watch.first_sync()) == (1_000.0, False, "running")
    clock.now += STALL_SECONDS - 1
    assert not watch.observe(_meter(downloaded=0)).stalled          # the long queued wait is not a stall yet
    clock.now += 2
    assert watch.observe(_meter(downloaded=0)).stalled and watch.first_sync() == "stalled"
    clock.now += 10
    moved = watch.observe(_meter(downloaded=1))                     # one asset arrives: moving again
    assert not moved.stalled and moved.last_progress == clock.now and moved.running_since == 1_000.0


def test_a_node_that_does_not_answer_is_never_called_stalled():
    clock = _Clock()
    watch = SyncProgressWatch(clock=clock)
    watch.observe(_meter(downloaded=5))
    clock.now += STALL_SECONDS * 3
    assert not watch.observe(_meter(state="unavailable", downloaded=None)).stalled


def test_a_finished_sync_resets_the_watch():
    watch = SyncProgressWatch(clock=_Clock())
    watch.observe(_meter(downloaded=5))
    done = watch.observe(_meter(state="synced", downloaded=565, compiled=565))
    assert (done.running_since, watch.first_sync()) == (None, "")


@pytest.mark.parametrize(("first_sync", "klass", "words"), [
    ("running", health.HealthClass.INFO, "Setting up"),
    ("stalled", health.HealthClass.ACTION, "stopped making progress"),
    ("", health.HealthClass.ACTION, "the threat ruleset is empty"),
])
def test_the_empty_ruleset_item_follows_the_first_sync(first_sync, klass, words):
    inputs = dataclasses.replace(HealthInputs(node_reachable=True, ruleset_age_s=10.0, sync_interval_s=3600.0,
                                              rule_count=0), first_sync=first_sync)
    (item,) = [i for i in health.operator_health(inputs) if "ruleset" in i.message or "threat graph" in i.message]
    assert item.klass is klass and words in item.message


def test_the_meter_route_carries_the_phase(monkeypatch):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    monkeypatch.setattr(sync_meter, "WATCH", SyncProgressWatch(clock=_Clock()))
    monkeypatch.setattr(sync_meter, "read_sync_meter", lambda cfg, **kwargs: _meter(downloaded=0))
    app = FastAPI()
    sync_meter.register_sync_meter_routes(app, load_config=lambda: object(), node_reachable=lambda cfg: True,
                                          verified_rules=lambda cfg: 0)
    body = TestClient(app).get("/api/verified-sync").json()
    assert body["phase"] == "queued" and body["running_since"] == 1_000.0 and "lining up" in body["phase_text"]


def test_a_dashboard_restart_keeps_the_running_time(tmp_path):
    """Bench 2026-10-22: after a dashboard restart the line said "running 1 min" over a
    sync that had run for half an hour. The times are remembered in the Blackbox home."""
    clock, store = _Clock(), tmp_path / "sync_progress.json"
    SyncProgressWatch(clock=clock, store=lambda: store).observe(_meter(downloaded=5))
    clock.now += 1_800
    restarted = SyncProgressWatch(clock=clock, store=lambda: store).observe(_meter(downloaded=5))
    assert restarted.running_since == 1_000.0 and restarted.last_progress == 1_000.0
    SyncProgressWatch(clock=clock, store=lambda: store).observe(_meter(state="synced", downloaded=565, compiled=565))
    assert not store.exists()                                        # a finished sync forgets


def test_an_unreadable_memory_only_restarts_the_count(tmp_path):
    store = tmp_path / "sync_progress.json"
    store.write_text("not json", encoding="utf-8")
    assert SyncProgressWatch(clock=_Clock(), store=lambda: store).observe(_meter(downloaded=5)).running_since == 1_000.0
