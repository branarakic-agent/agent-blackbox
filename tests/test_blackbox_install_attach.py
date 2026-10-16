"""The installers protect the Hermes home they set up, and no other agent unless the operator says so.

Hermes catalog review (22cb7e62): every Hermes profile is its own trust and credential boundary,
yet the installer's `blackbox attach` enabled Blackbox in every home it found. Now the installer
names its own home, and every other agent waits for a "yes" at the terminal (the bare
`blackbox attach`, which attaches nothing with no terminal — tested in
tests/plugins/test_blackbox_attach.py) or BLACKBOX_ATTACH_ALL=1 for scripted installs. These tests
run the installer's real `attach_all_agents` with a fake `hermes` that records what it is asked.
"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
INSTALL_SH = REPO / "scripts" / "blackbox-install.sh"
INSTALL_PS1 = REPO / "scripts" / "blackbox-install.ps1"


def _body(name: str) -> str:
    text = INSTALL_SH.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", text, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _run(tmp_path: Path, *, attach_all: str = "") -> list[str]:
    calls = tmp_path / "calls"
    calls.write_text("", encoding="utf-8")
    hermes = tmp_path / "hermes"
    hermes.write_text(f'#!/bin/sh\necho "$*" >> {shlex.quote(str(calls))}\nexit 0\n', encoding="utf-8")
    hermes.chmod(0o755)
    script = f"""
HERMES_BIN={shlex.quote(str(hermes))}
HERMES_HOME={shlex.quote(str(tmp_path / "hermes-home"))}
heading() {{ :; }}; step() {{ :; }}; ok() {{ :; }}; warn() {{ :; }}
attach_all_agents() {{
{_body("attach_all_agents")}
}}
attach_all_agents
"""
    env = {**os.environ, "BLACKBOX_ATTACH_ALL": attach_all}
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False, env=env)
    assert result.returncode == 0, result.stderr
    return calls.read_text(encoding="utf-8").splitlines()


def test_unattended_the_installer_names_only_its_own_home(tmp_path):
    calls = _run(tmp_path)
    assert calls == [f"blackbox attach {tmp_path / 'hermes-home'}", "blackbox attach"]
    assert not any("--all" in call for call in calls)


@pytest.mark.parametrize("value", ["1", "true", "YES"])
def test_attach_all_opts_a_scripted_install_into_every_agent(tmp_path, value):
    assert _run(tmp_path, attach_all=value) == [f"blackbox attach {tmp_path / 'hermes-home'}", "blackbox attach --all"]


def test_the_windows_installer_names_its_own_home_and_asks_for_the_rest():
    text = INSTALL_PS1.read_text(encoding="utf-8")
    body = text[text.index("function Protect-AllAgents"):text.index("# ── Guided next steps")]
    assert "& $HermesBin blackbox attach $HermesHome" in body
    assert "& $HermesBin blackbox attach --all" in body and "BLACKBOX_ATTACH_ALL" in body
    calls = [line.strip() for line in body.splitlines() if line.strip().startswith("& $HermesBin blackbox attach")]
    assert calls == ["& $HermesBin blackbox attach $HermesHome", "& $HermesBin blackbox attach --all",
                     "& $HermesBin blackbox attach"]   # the last, bare: lists the others and asks
