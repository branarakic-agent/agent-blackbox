"""``blackbox dashboard`` stops only a Blackbox dashboard on its port (2026-10-22, FIX-0159).

The restart path used to SIGTERM (then SIGKILL) every pid listening on the
port. The port is a shared machine resource and the working rule is never to
kill a process you did not start, so a stranger on the port is named and left
alone, and the command exits 1 instead of binding over it.
"""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from plugins.blackbox.dashboard import command


class _Proc:
    def __init__(self, argv):
        self._argv = argv

    def cmdline(self):
        return self._argv


@pytest.fixture
def killed(monkeypatch):
    sent: list[tuple[int, int]] = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: sent.append((pid, sig)))
    return sent


def _fake_psutil(monkeypatch, procs: dict[int, list[str]]):
    import psutil

    monkeypatch.setattr(psutil, "Process", lambda pid: _Proc(procs[pid]))
    monkeypatch.setattr(psutil, "pid_exists", lambda pid: False)


def test_a_blackbox_dashboard_on_the_port_is_stopped(monkeypatch, killed):
    _fake_psutil(monkeypatch, {4242: ["/x/venv/bin/hermes", "blackbox", "dashboard"]})
    monkeypatch.setattr(command, "_listening_pids", lambda port: {4242})

    assert command._replace_existing_dashboard(9700) is True
    assert [pid for pid, _ in killed] == [4242]


def test_a_stranger_on_the_port_is_named_and_left_alone(monkeypatch, killed, capsys):
    _fake_psutil(monkeypatch, {777: ["/usr/bin/node", "other-product/server.js"]})
    monkeypatch.setattr(command, "_listening_pids", lambda port: {777})

    assert command._replace_existing_dashboard(9700) is False
    assert killed == []
    out = capsys.readouterr().out
    assert "777 (node other-product/server.js)" in out and "--port 9701" in out


def test_an_unreadable_process_is_never_ours(monkeypatch, killed):
    """psutil denied or the process gone: unknown is not a licence to kill (LES-011)."""
    import psutil

    def denied(pid):
        raise psutil.AccessDenied(pid)
    monkeypatch.setattr(psutil, "Process", denied)
    monkeypatch.setattr(command, "_listening_pids", lambda port: {31337})

    assert command._replace_existing_dashboard(9700) is False
    assert killed == []


def test_the_command_exits_without_binding_when_the_port_is_a_strangers(monkeypatch):
    bound: list[int] = []
    monkeypatch.setattr(command, "_replace_existing_dashboard", lambda port: False)
    monkeypatch.setattr(command, "load_blackbox_config", lambda: SimpleNamespace(dashboard_port=9700))
    from plugins.blackbox.dashboard import server
    monkeypatch.setattr(server, "start_dashboard", lambda port: bound.append(port))

    assert command.cmd_dashboard(SimpleNamespace(port=None)) == 1
    assert bound == []


def test_nothing_listening_means_the_port_is_ours(monkeypatch, killed):
    monkeypatch.setattr(command, "_listening_pids", lambda port: set())

    assert command._replace_existing_dashboard(9700) is True
    assert killed == []
