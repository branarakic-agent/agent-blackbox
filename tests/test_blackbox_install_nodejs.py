"""The installer uses a Node.js that nvm installed on an earlier run (KI-418).

nvm puts Node under ~/.nvm/versions, which a fresh, non-interactive shell does not have on PATH.
Every re-run therefore announced "Node.js 22+ not found — installing it automatically" and ran
`nvm install` again (seen on the trader bench, 2026-10-15). ensure_node now asks nvm first.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from pathlib import Path

INSTALL_SH = Path(__file__).resolve().parents[1] / "scripts" / "blackbox-install.sh"


def _body(name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\)\s*\{{\s*\n(?P<body>.*?)^\}}", INSTALL_SH.read_text(encoding="utf-8"),
                      re.MULTILINE | re.DOTALL)
    assert match is not None, f"{name}() not found"
    return match["body"]


def _ensure_node(tmp_path: Path, *, installed_major: int) -> tuple[subprocess.CompletedProcess, str]:
    nvm_dir, node_bin, calls = tmp_path / "nvm", tmp_path / "nvm-node" / "bin", tmp_path / "calls"
    nvm_dir.mkdir(); node_bin.mkdir(parents=True); calls.write_text("", encoding="utf-8")
    for name, version in (("node", f"v{installed_major}.3.0"), ("npm", "10.9.0")):
        (node_bin / name).write_text(f"#!/bin/sh\necho {version}\n", encoding="utf-8")
        (node_bin / name).chmod(0o755)
    # A stand-in nvm: `use` puts its Node on PATH (as the real one does); every call is recorded.
    (nvm_dir / "nvm.sh").write_text(
        f'nvm() {{ echo "nvm $*" >> {shlex.quote(str(calls))}; '
        f'if [ "$1" = use ]; then PATH={shlex.quote(str(node_bin))}:$PATH; fi; }}\n', encoding="utf-8")
    script = f"""
set -euo pipefail
ok() {{ echo "OK $*"; }}
warn() {{ echo "WARN $*"; }}
step() {{ :; }}
_node_manual_hint() {{ :; }}
curl() {{ echo "curl $*" >> {shlex.quote(str(calls))}; return 1; }}
NODE_MAJOR=22
SKIP_DKG=false
NVM_DIR={shlex.quote(str(nvm_dir))}
PATH=/usr/bin:/bin
_node_ok() {{
{_body("_node_ok")}
}}
ensure_node() {{
{_body("ensure_node")}
}}
ensure_node
echo "HAS_NODE=$HAS_NODE"
"""
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=False)
    return result, calls.read_text(encoding="utf-8")


def test_a_node_nvm_installed_earlier_is_used_without_a_second_install(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=22)

    assert result.returncode == 0, result.stderr
    assert "HAS_NODE=true" in result.stdout and "installed earlier with nvm" in result.stdout
    assert "not found" not in result.stdout and "nvm install" not in calls


def test_an_older_nvm_node_still_triggers_the_install(tmp_path):
    result, calls = _ensure_node(tmp_path, installed_major=18)

    assert "not found" in result.stdout and "nvm install 22" in calls
