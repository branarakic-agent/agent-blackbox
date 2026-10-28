"""The verified graph stays current in real time (Amos, 2026-10-12).

A correction published at 01:07 reached every bench's node within 30 s but sat
unread for up to an hour, because the dashboard's ruleset worker slept the full
``sync_interval``. Now a cheap count probe (``GrowthWatch``) wakes the worker
and ``request_refresh_now`` moves the cached generation's schedule to now.
"""

from __future__ import annotations

import time
from typing import List, Optional

import pytest

from plugins.blackbox.dashboard import sync_timing
from plugins.blackbox.kernel import constants
from plugins.blackbox.ruleset import compiler, disk_cache, pulse_beat, refresh_cycle
from plugins.blackbox.ruleset.partitions import growth_watch
from plugins.blackbox.ruleset.partitions.growth_watch import GrowthWatch


class _Clock:
    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


class _Counts:
    """A scripted count source that records how often it was asked."""

    def __init__(self, value: Optional[int]) -> None:
        self.value = value
        self.calls = 0

    def __call__(self) -> Optional[int]:
        self.calls += 1
        return self.value


@pytest.fixture
def watch_parts():
    clock, node, listed = _Clock(), _Counts(564), _Counts(564)
    return GrowthWatch(node, listed, clock), clock, node, listed


# ------------------------------------------------------------------ the decision


def test_new_assets_on_the_node_trigger_one_refresh(watch_parts):
    watch, clock, node, _listed = watch_parts
    node.value = 565

    assert watch.check() is True
    clock.now += growth_watch.PROBE_EVERY_SECONDS
    assert watch.check() is False            # the same count never asks twice …
    clock.now += growth_watch.MIN_TRIGGER_GAP_SECONDS
    assert watch.check() is False            # … not even after the trigger gap (a failed refresh: the hourly backstop)


def test_no_growth_never_triggers(watch_parts):
    watch, clock, node, _listed = watch_parts
    for held in (564, 563):
        node.value = held
        clock.now += growth_watch.PROBE_EVERY_SECONDS
        assert watch.check() is False


@pytest.mark.parametrize("node_value, listed_value", [(None, 564), (565, None), (None, None)])
def test_could_not_tell_never_triggers(watch_parts, node_value, listed_value):
    watch, _clock, node, listed = watch_parts
    node.value, listed.value = node_value, listed_value

    assert watch.check() is False


def test_the_node_is_asked_at_most_once_per_probe_interval(watch_parts):
    watch, clock, node, _listed = watch_parts
    watch.check()
    watch.check()
    clock.now += growth_watch.PROBE_EVERY_SECONDS - 1
    watch.check()
    assert node.calls == 1
    clock.now += 1
    watch.check()
    assert node.calls == 2


def test_more_growth_waits_out_the_trigger_gap(watch_parts):
    watch, clock, node, _listed = watch_parts
    node.value = 565
    assert watch.check() is True
    node.value = 566
    clock.now += growth_watch.PROBE_EVERY_SECONDS
    assert watch.check() is False            # inside MIN_TRIGGER_GAP_SECONDS
    clock.now += growth_watch.MIN_TRIGGER_GAP_SECONDS
    assert watch.check() is True


# ------------------------------------------------------------------ the worker's wait


def test_the_wait_ends_early_when_woken():
    wakes: list[int] = []

    def wake() -> bool:
        wakes.append(1)
        return len(wakes) == 3

    started = time.monotonic()
    stopped = sync_timing.wait_or_wake(60.0, lambda: False, wake, tick_s=0.001)

    assert stopped is False and len(wakes) == 3
    assert time.monotonic() - started < 5.0


def test_the_wait_reports_a_stop_request():
    assert sync_timing.wait_or_wake(60.0, lambda: True, lambda: False, tick_s=0.001) is True


def test_a_failing_wake_check_never_ends_the_loop(caplog):
    def broken() -> bool:
        raise RuntimeError("node gone")

    assert sync_timing.wait_or_wake(0.01, lambda: False, broken, tick_s=0.001) is False
    assert "verified growth check failed" in caplog.text


# ------------------------------------------------------------------ the schedule write-through (real, no stubs: LES-020)


class _Config:
    sync_interval = 3600
    context_graph_id = "cg"
    dkg_url = constants.DEFAULT_DKG_URL
    dkg_home = None


def test_request_refresh_now_makes_the_cached_generation_due_on_disk_and_in_memory(monkeypatch, tmp_path):
    monkeypatch.setattr(constants, "blackbox_home", lambda: tmp_path)
    monkeypatch.setattr(refresh_cycle, "_memory", refresh_cycle._new_memory())
    rs = compiler.build_from_rows([])
    rs.context_graph_id = "cg"
    rs.synced_at = time.time()                      # compiled just now: not due for an hour
    disk_cache._write_cache(rs)
    refresh_cycle._memory.store(rs)
    assert refresh_cycle.peek(_Config()).refresh_due(3600) > time.time() + 3000

    assert pulse_beat.request_refresh_now(_Config()) is True

    assert refresh_cycle.peek(_Config()).refresh_due(3600) <= time.time()
    assert disk_cache._read_cache().refresh_due(3600) <= time.time()


def test_a_sync_that_fell_due_while_the_machine_slept_starts_right_after_wake():
    """A sleeping Mac freezes the worker mid-wait; on wake the wall clock is hours on.
    The wait must end at the next tick, not resume its countdown (Mac, 2026-10-18)."""
    now = [1_000.0]
    ticks: list[int] = []

    def clock() -> float:
        return now[0]

    def wake() -> bool:
        ticks.append(1)
        if len(ticks) == 2:
            now[0] += 4 * 3600.0   # the lid closes here and opens four hours later
        return False

    # A tick budget far below the hour: code that resumed the countdown is stopped here
    # (returns True) instead of hanging the suite for an hour.
    stopped = sync_timing.wait_or_wake(3600.0, lambda: len(ticks) > 50, wake, tick_s=0.001, clock=clock)

    assert stopped is False   # the wait ended because the sync is due, not because it was stopped
    assert len(ticks) == 2


def test_a_clock_set_backwards_never_stretches_the_wait():
    now = [1_000.0]

    def clock() -> float:
        now[0] -= 3600.0   # every reading an hour earlier than the last
        return now[0]

    started = time.monotonic()
    stopped = sync_timing.wait_or_wake(0.05, lambda: False, lambda: False, tick_s=0.001, clock=clock)

    assert stopped is False
    assert time.monotonic() - started < 5.0

