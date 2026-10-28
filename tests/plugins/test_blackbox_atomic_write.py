"""One torn-free write for the whole plugin (2026-10-22).

31 files hand-rolled "temp file + os.replace" in three spellings, one of them
creating the file 0600 and the others not, with no single place to fix. Now
``kernel.bounded_files.atomic_write`` is the one implementation, and a guard
names the few files still allowed to call ``os.replace`` themselves (the ones
that also fsync, and the standalone installer helper).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from plugins.blackbox.kernel.bounded_files import atomic_write
from plugins.blackbox.kernel.health import days_between, today_utc

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"

#: Files that may call os.replace themselves: the implementation, writers that also
#: fsync their secret (a torn-free write is not a durable one), and the installer helper
#: that runs standalone without the plugin on its path.
MAY_REPLACE = {
    "kernel/bounded_files/atomic_write.py",
    "curate/console/root_signer.py",
    "curate/console/roster.py",
    "curate/lab/jobs.py",
    "curate/service/disputes.py",
    "sync/process_limits.py",
    "setup/blackbox-dkg-runtime-fingerprint.py",
}


def test_a_write_lands_whole_and_creates_its_folder(tmp_path):
    target = tmp_path / "deep" / "state.json"

    atomic_write(target, '{"a": 1}')
    atomic_write(target, '{"a": 2}')

    assert target.read_text(encoding="utf-8") == '{"a": 2}'
    assert [p.name for p in target.parent.iterdir()] == ["state.json"]   # no temp file left behind


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_a_secret_is_created_0600_from_the_start(tmp_path):
    target = tmp_path / "key.pem"

    atomic_write(target, "secret", mode=0o600)

    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text(encoding="utf-8") == "secret"


def test_no_module_rolls_its_own_replace():
    offenders = sorted(
        str(path.relative_to(PLUGIN))
        for path in PLUGIN.rglob("*.py")
        if "os.replace(" in path.read_text(encoding="utf-8-sig")
        and str(path.relative_to(PLUGIN)) not in MAY_REPLACE
    )
    assert offenders == [], f"use kernel.bounded_files.atomic_write instead: {offenders}"


def test_days_between_reads_iso_days_and_never_raises():
    assert days_between("2026-10-01", "2026-10-22") == 21
    assert days_between("2026-10-22", "2026-10-01") == -21
    assert days_between("not a day", "2026-10-22") == 0
    assert len(today_utc()) == 10 and today_utc()[4] == "-"
