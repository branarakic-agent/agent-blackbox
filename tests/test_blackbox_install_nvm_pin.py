"""nvm's installer runs only after its bytes match a pinned sha256 (Hermes plugin catalog review, 2026-10-16).

The installer used to run ``curl … nvm/v0.40.3/install.sh | bash`` with no integrity check. It now
downloads the script to a file, compares its sha256 with ``NVM_INSTALL_SHA256`` and runs it only on
a match. These tests drive the real ``install_nvm_verified`` body with a stand-in ``curl``: a match
runs the script, a mismatch or a failed download runs nothing and leaves no temp file, and no line
of the installer pipes a download into a shell.
"""

from __future__ import annotations

import hashlib
import re
import shlex
import subprocess
import urllib.request
from pathlib import Path

import pytest

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"
TEXT = INSTALL_SH.read_text(encoding="utf-8")


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", TEXT, re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _pin(name: str) -> str:
    match = re.search(rf'^{name}="([^"]+)"$', TEXT, re.MULTILINE)
    assert match is not None, f"{name} not set"
    return match[1]


def _run(tmp_path: Path, *, served: str | None, pinned_sha: str) -> tuple[subprocess.CompletedProcess, Path, Path]:
    """Run install_nvm_verified with a curl that serves *served* (None = the download fails)."""
    ran, temp = tmp_path / "ran", tmp_path / "tmp"
    temp.mkdir()
    payload = tmp_path / "payload.sh"
    if served is not None:
        payload.write_text(served, encoding="utf-8")
    serve = f'cp {shlex.quote(str(payload))} "$out"' if served is not None else "return 22"
    fake_curl = f'curl() {{ out=""; while [ $# -gt 0 ]; do [ "$1" = -o ] && out="$2"; shift; done; {serve}; }}'
    script = f"""
set -euo pipefail
warn() {{ echo "WARN $*"; }}
{fake_curl}
TMPDIR={shlex.quote(str(temp))}
NVM_INSTALL_VERSION_PIN=v0.40.3
NVM_INSTALL_SHA256={pinned_sha}
export RAN_MARKER={shlex.quote(str(ran))}
_sha256_of() {{
{_body("_sha256_of")}
}}
install_nvm_verified() {{
{_body("install_nvm_verified")}
}}
if install_nvm_verified; then echo "RESULT ok"; else echo "RESULT failed"; fi
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    return result, ran, temp


GOOD = 'touch "$RAN_MARKER"\n'


def test_a_script_matching_the_pin_is_run(tmp_path):
    result, ran, temp = _run(tmp_path, served=GOOD, pinned_sha=hashlib.sha256(GOOD.encode()).hexdigest())
    assert "RESULT ok" in result.stdout, result.stdout + result.stderr
    assert ran.exists()
    assert list(temp.iterdir()) == []   # the downloaded script is removed


def test_a_script_that_differs_from_the_pin_is_never_run(tmp_path):
    result, ran, temp = _run(tmp_path, served=GOOD + "# changed\n", pinned_sha=hashlib.sha256(GOOD.encode()).hexdigest())
    assert "RESULT failed" in result.stdout
    assert "did not match its pinned checksum" in result.stdout
    assert not ran.exists()
    assert list(temp.iterdir()) == []


def test_a_failed_download_runs_nothing(tmp_path):
    result, ran, temp = _run(tmp_path, served=None, pinned_sha="0" * 64)
    assert "RESULT failed" in result.stdout
    assert not ran.exists()
    assert list(temp.iterdir()) == []


def test_the_pin_is_a_sha256_for_the_pinned_release():
    assert re.fullmatch(r"[0-9a-f]{64}", _pin("NVM_INSTALL_SHA256"))
    assert re.fullmatch(r"v\d+\.\d+\.\d+", _pin("NVM_INSTALL_VERSION_PIN"))


def _executed_pipe_to_shell(line: str) -> bool:
    """A download piped into a shell, outside a comment and outside a quoted hint the installer prints."""
    match = re.search(r"\b(curl|wget)\b[^|#]*\|\s*(ba|z)?sh\b", line)
    return bool(match) and not line.lstrip().startswith("#") and line[:match.start()].count('"') % 2 == 0


def test_no_installer_line_pipes_a_download_into_a_shell():
    assert [line for line in TEXT.splitlines() if _executed_pipe_to_shell(line)] == []
    assert _executed_pipe_to_shell("curl -fsSL https://example.invalid/x.sh | bash")   # the check sees the old shape


def test_ensure_node_installs_nvm_only_through_the_verified_path():
    body = _body("ensure_node")
    assert "install_nvm_verified" in body
    assert "nvm-sh/nvm" not in body


@pytest.mark.integration
def test_the_pin_matches_the_published_script():
    url = f"https://raw.githubusercontent.com/nvm-sh/nvm/{_pin('NVM_INSTALL_VERSION_PIN')}/install.sh"
    with urllib.request.urlopen(url, timeout=30) as response:   # a fixed https URL
        assert hashlib.sha256(response.read()).hexdigest() == _pin("NVM_INSTALL_SHA256")
