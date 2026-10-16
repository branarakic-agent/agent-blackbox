"""Community sharing in the installers' config writers: off on a fresh install, never switched on by
an installer, kept on only for an operator who opted in (Hermes plugin catalog review, 2026-10-16).

Split out of test_blackbox_install_llm_setup.py (which keeps the config-writer harness these tests
call) so that file stays under its size cap.
"""

from __future__ import annotations

import sys
from pathlib import Path

from tests.test_blackbox_install_llm_setup import (
    INSTALL_PS1,
    INSTALL_SH,
    _configure,
    _extract_powershell_function_body,
    _run_unix_blackbox_config_writer,
    _write_config,
)


def _opted_out_home(tmp_path: Path) -> Path:
    import json
    home = tmp_path / "opted-out-home"
    home.mkdir()
    (home / "sharing_consent.json").write_text(json.dumps({
        "terms_hash": "", "terms_version": "", "accepted_at": "", "withdrawn_at": "2026-10-01T00:00:00+00:00"}),
        encoding="utf-8")
    return home


def _opted_in_home(tmp_path: Path) -> Path:
    import json
    home = tmp_path / "opted-in-home"
    home.mkdir()
    (home / "sharing_consent.json").write_text(json.dumps({
        "terms_hash": "a", "terms_version": "1.4", "accepted_at": "2026-10-16T00:00:00+00:00", "withdrawn_at": ""}),
        encoding="utf-8")
    return home


def test_unix_installer_fresh_config_leaves_community_sharing_off(tmp_path: Path) -> None:
    """Sharing is opt-in (2026-10-16, Hermes plugin catalog review): a fresh install writes
    `report: false` and never records an acceptance on the operator's behalf."""
    home = tmp_path / "fresh-home"
    blackbox = _configure(tmp_path, tmp_path / "config.yaml", home)

    assert blackbox["report"] is False and "sharing_default" not in blackbox
    assert not (home / "sharing_consent.json").exists()
    assert blackbox["daily_report_limit"] == 100   # the plugin default; 0 meant "no cap" (Refine R1)


def test_unix_installer_turns_off_sharing_that_only_the_old_default_turned_on(tmp_path: Path) -> None:
    """A 2026-10-12 install: `report: true` and the default marker, but no acceptance on record."""
    config_path = _write_config(tmp_path, "      report: true\n      sharing_default: on-2026-10-12\n")
    blackbox = _configure(tmp_path, config_path, tmp_path / "home")
    assert blackbox["report"] is False and "sharing_default" not in blackbox


def test_unix_installer_keeps_sharing_on_for_an_operator_who_opted_in(tmp_path: Path) -> None:
    config_path = _write_config(tmp_path, "      report: true\n      sharing_default: on-2026-10-12\n")
    blackbox = _configure(tmp_path, config_path, _opted_in_home(tmp_path))
    assert blackbox["report"] is True and "sharing_default" not in blackbox


def test_unix_installer_never_overrides_an_opt_out_or_a_later_choice(tmp_path: Path) -> None:
    opted_out = _configure(tmp_path, _write_config(tmp_path, "      report: false\n"), _opted_out_home(tmp_path))
    assert opted_out["report"] is False                                         # an opt-out on record is respected
    later = tmp_path / "later"
    later.mkdir()
    chosen = _configure(later, _write_config(later, "      report: false\n      sharing_default: on-2026-10-12\n"),
                        later / "home")
    assert chosen["report"] is False                                            # off after the default step: kept off


def test_windows_installer_fresh_config_leaves_community_sharing_off() -> None:
    writer = _extract_powershell_function_body("Enable-AndConfigure")

    assert '"report": False,' in writer and '"report": True' not in writer
    assert '"daily_report_limit": 100' in writer
    installer = INSTALL_PS1.read_text(encoding="utf-8")
    assert 'blackbox.pop("sharing_default", None)' in installer            # the old default's marker is removed
    assert "SHARING_DEFAULT_MARK" not in installer
    assert '"daily_report_limit": 9999' not in writer


def test_unix_installer_turns_sharing_off_when_it_cannot_read_the_opt_out_state(tmp_path: Path) -> None:
    """Without the product code the installer cannot ask whether the operator
    opted out, so it answers "no" and sends nothing rather than guess (fail closed)."""
    helper = INSTALL_SH.read_text(encoding="utf-8").split("def _consent_in_force(checkout):", 1)[1].split("\nif ", 1)[0]
    namespace: dict = {"sys": sys}
    exec("def _consent_in_force(checkout):" + helper, namespace)
    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def failing_import(name, *args, **kwargs):
        if name.startswith("plugins.blackbox"):
            raise ImportError("no checkout")
        return real_import(name, *args, **kwargs)

    import builtins
    original = builtins.__import__
    builtins.__import__ = failing_import
    try:
        assert namespace["_consent_in_force"]("") is False
    finally:
        builtins.__import__ = original


def test_windows_installer_migrates_stale_community_sharing_opt_in() -> None:
    writer = INSTALL_PS1.read_text(encoding="utf-8")

    # KI-184: the forced migration is gone on Windows too — sharing stays on for a
    # consenting node (the product's consent code decides), only 0 is repaired.
    assert 'for k, v in {"report": False, "daily_report_limit": 20}.items()' not in writer
    assert 'if blackbox.get("report") is True and not _consent_in_force(repo_dir):' in writer
    assert 'if blackbox.get("daily_report_limit") in (0, "0", 20, "20")' in writer
    # the checkout for a curl install, the plugin folder in setup-only mode (`blackbox setup`)
    assert "$GraphPeerId $(if ($env:BLACKBOX_PLUGIN_DIR) { $env:BLACKBOX_PLUGIN_DIR } else { $RepoDir })" in writer


def test_unix_installer_keeps_sharing_on_when_a_consent_record_is_in_force(tmp_path: Path) -> None:
    """KI-184: a re-run or upgrade must not switch a consenting node's sharing off.
    The installer asks the product's own consent code (one implementation)."""
    import json

    from plugins.blackbox.community import consent

    home = tmp_path / "bbhome"
    home.mkdir()
    (home / "sharing_consent.json").write_text(json.dumps({
        "terms_hash": consent.terms_hash(consent.terms_text()),
        "terms_version": "1.0", "accepted_at": "2026-10-03T00:00:00Z", "withdrawn_at": "",
    }), encoding="utf-8")
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        "plugins:\n  entries:\n    blackbox:\n      report: true\n      daily_report_limit: 500\n",
        encoding="utf-8",
    )
    configured = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9320",
        dkg_home=tmp_path / ".dkg",
        dkg_bin=tmp_path / "dkg" / "node_modules" / ".bin" / "dkg",
        repo_dir=str(Path(__file__).resolve().parents[1]),
        env={"BLACKBOX_HOME": str(home)},
    )
    blackbox = configured["plugins"]["entries"]["blackbox"]
    assert blackbox["report"] is True
    assert blackbox["daily_report_limit"] == 500   # an operator-chosen cap is kept


def test_unix_installer_turns_sharing_off_for_an_operator_who_opted_out(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text("plugins:\n  entries:\n    blackbox:\n      report: true\n      daily_report_limit: 0\n", encoding="utf-8")
    configured = _run_unix_blackbox_config_writer(
        config_path,
        dkg_url="http://127.0.0.1:9320",
        dkg_home=tmp_path / ".dkg",
        dkg_bin=tmp_path / "dkg" / "node_modules" / ".bin" / "dkg",
        repo_dir=str(Path(__file__).resolve().parents[1]),
        env={"BLACKBOX_HOME": str(_opted_out_home(tmp_path))},
    )
    blackbox = configured["plugins"]["entries"]["blackbox"]
    assert blackbox["report"] is False
    assert blackbox["daily_report_limit"] == 100   # the invalid pre-R1 "no cap" is repaired
