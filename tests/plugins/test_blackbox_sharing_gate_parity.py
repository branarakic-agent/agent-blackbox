"""The OpenClaw bridge and the Python plugin answer "may this machine share?"
the same way (LES-029: a second implementation is only as current as its test).

Sharing is opt-in (2026-10-16): on only with an acceptance and no opt-out;
every malformed record reads as no record (off). The TypeScript half is
``integrations/openclaw/test/sharing-gate-parity.mjs``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from plugins.blackbox.community import consent

REPO = Path(__file__).resolve().parents[2]
TSX = REPO / "node_modules" / ".bin" / "tsx"
SCRIPT = REPO / "integrations" / "openclaw" / "test" / "sharing-gate-parity.mjs"

#: Record-file contents (None = no file) and the answer both runtimes must give.
CASES = [
    (None, False),                                                                          # the default: off
    (json.dumps({"terms_hash": "a", "terms_version": "1.2", "accepted_at": "t", "withdrawn_at": ""}), True),
    (json.dumps({"terms_hash": "a", "terms_version": "1.2", "accepted_at": "t", "withdrawn_at": "2026-10-12"}), False),
    (json.dumps({"terms_hash": "", "terms_version": "", "accepted_at": "", "withdrawn_at": "2026-10-12"}), False),
    (json.dumps({"withdrawn_at": "2026-10-12"}), False),                                    # an opt-out missing other fields
    (json.dumps({"terms_hash": "old", "terms_version": "1.0", "accepted_at": "t", "withdrawn_at": ""}), True),  # old terms
    (json.dumps({"terms_hash": "a", "terms_version": "1.3", "accepted_at": "", "withdrawn_at": ""}), False),   # no acceptance
    (json.dumps({"accepted_at": None, "withdrawn_at": None}), False),                       # null is no value
    (json.dumps({"accepted_at": 1, "withdrawn_at": ""}), False),                            # a number is no value
    (json.dumps({"accepted_at": "t"}), True),                                               # an acceptance alone
    ("{nope", False), ("[]", False), ('"text"', False), ("null", False),                    # malformed: no record
]


def _python_answer(home: Path, content):
    home.mkdir()
    if content is not None:
        (home / "sharing_consent.json").write_text(content, encoding="utf-8")
    return consent.in_force()


def test_python_follows_the_shared_cases(real_consent, monkeypatch, tmp_path):
    for index, (content, expected) in enumerate(CASES):
        home = tmp_path / f"home{index}"
        monkeypatch.setenv("BLACKBOX_HOME", str(home))
        assert _python_answer(home, content) is expected, content


@pytest.mark.skipif(not TSX.exists() or shutil.which("node") is None, reason="tsx/node not installed")
def test_both_runtimes_answer_identically(tmp_path):
    case_file = tmp_path / "cases.json"
    case_file.write_text(json.dumps([content for content, _ in CASES]), encoding="utf-8")
    result = subprocess.run([str(TSX), str(SCRIPT), str(case_file)], capture_output=True, text=True, timeout=120,
                            cwd=str(REPO), check=True)
    assert json.loads(result.stdout) == [expected for _, expected in CASES]
