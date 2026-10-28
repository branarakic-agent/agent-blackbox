"""Reading a credential the way Hermes hands it out — the one route for secrets.

Blackbox needs one credential of its own: the optional LLM reviewer's API key,
named by a variable (``BLACKBOX_LLM_API_KEY``, or the variable saved in
``llm.api_key_env`` such as ``OPENAI_API_KEY``). Hermes decides which value a
variable has for the profile being served: ``agent.secret_scope.get_secret``
reads the active profile's scope, and under multi-profile multiplexing it
refuses rather than hand one profile another profile's key. A bare
``os.environ`` read can do exactly that, so every secret Blackbox reads goes
through :func:`read_host_secret` — never ``os.environ``, never a ``.env`` file,
never another program's login (Hermes plugin catalog rule 11).

Outside Hermes (the OpenClaw bridge's Python tests, a standalone script) there
is no ``agent.secret_scope`` to ask, and the process environment is the only
source there is.

Usage::

    key = read_host_secret("OPENAI_API_KEY")
    if not key:
        ...   # unset, an invalid name, or Hermes refused it for this turn
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)


__all__ = ["read_host_secret"]   # the surface other modules may import


def read_host_secret(name: str) -> str:
    """The value Hermes gives the variable *name* for the profile being served, or "".

    *name* must be a plain variable name (ASCII identifier); anything else — such
    as a ``llm.api_key_env`` value an operator mistyped — answers "" without a read.
    A refusal under multiplexing (no profile scope for this turn) answers "" and is
    logged at WARNING: the reviewer then runs without a key, it never borrows one.
    """
    if not (name and name.isascii() and name.isidentifier()):
        return ""
    try:
        from agent.secret_scope import UnscopedSecretError, get_secret_str
    except ImportError:  # not running inside Hermes: the process environment is the source
        return os.environ.get(name, "").strip()
    try:
        return get_secret_str(name).strip()
    except UnscopedSecretError:
        logger.warning("blackbox: Hermes gave no profile scope for %s; the LLM reviewer runs without a key", name)
        return ""
