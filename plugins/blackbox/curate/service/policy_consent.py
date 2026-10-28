"""Standing consent to the automation policy, bound to its exact text (Community Curation C9, plan §07).

Every outward curator write is a legal act under the curator's key, so the
service signs on its own only after the operator has read and accepted the
automation policy. The acceptance names the policy's hash: when the policy
text changes — a new automatic action, another limit — the stored acceptance
no longer matches and the service stops signing until the operator accepts
the new text. Withdrawing is one command and takes effect on the next beat.

State: ``$BLACKBOX_HOME/curate/policy_consent.json`` — one class owns the
file, one lock, atomic writes. Local only; never shared.

Usage::

    consent = PolicyConsent()
    consent.accept(policy.policy_text(), key_hex=my_key, day="2026-10-03")
    consent.accepted(policy.policy_text())      # False after any change to the text, or a withdrawal
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .. import keys
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

_FILE = "policy_consent.json"


@dataclass(frozen=True)
class Acceptance:
    """One stored acceptance: the policy ``policy_hash`` it names, the UTC
    ``day`` it was given and the curator ``key`` it was given for."""

    policy_hash: str
    day: str
    key: str


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class PolicyConsent:
    """The operator's standing consent on this machine."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _FILE)

    def acceptance(self) -> Optional[Acceptance]:
        """The stored acceptance, or None (never given, withdrawn, or unreadable)."""
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            return Acceptance(policy_hash=str(data["policy_hash"]), day=str(data["day"]), key=str(data["key"]))
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def accepted(self, text: str, key_hex: str = "") -> bool:
        """True when the operator accepted exactly *text* (and, when given, for the curator key *key_hex*)."""
        held = self.acceptance()
        return held is not None and held.policy_hash == _hash(text) and (not key_hex or held.key == key_hex)

    def accept(self, text: str, *, key_hex: str, day: str) -> Acceptance:
        """Record that the operator accepted exactly *text* for *key_hex* on *day*."""
        acceptance = Acceptance(policy_hash=_hash(text), day=day, key=key_hex)
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self._path, json.dumps({"policy_hash": acceptance.policy_hash, "day": day, "key": key_hex}))
        return acceptance

    def withdraw(self) -> bool:
        """Remove the acceptance; True when there was one. The service signs nothing from its next beat."""
        with self._lock:
            try:
                self._path.unlink()
                return True
            except FileNotFoundError:
                return False
            except OSError as exc:
                logger.warning("blackbox curate: the policy consent could not be withdrawn (%s)", exc)
                raise
