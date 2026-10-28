"""Crypto secrets — wallet secrets recognised in text by their own structure.

Generic secret rules (``kernel/redaction.py``) match fixed shapes such as a key
prefix. Wallet secrets need more: a seed phrase is ordinary words until a
checksum proves it is a phrase. This sub-package holds those recognisers, used
by redaction (never store or send one) and by detection (flag or block an agent
handling one).

Public surface:

* :func:`find_seed_phrase_runs` / :class:`SeedPhraseRun` — BIP-39 seed phrases
  (MetaMask's Secret Recovery Phrase), checksum-verified;
* :func:`redact_seed_phrases` / :func:`seed_phrase_spans` and :data:`SEED_PHRASE_MARKER`;
* :func:`text_view.percent_decoded` — a text read the way a URL's receiver reads it;
* :func:`find_solana_secret_keys` / :func:`redact_solana_keys` and
  :data:`SOLANA_KEY_MARKER` — Solana secret keys (Phantom's exported key, the
  Solana CLI ``id.json``), verified by their Ed25519 self-check;
* :func:`find_bitcoin_private_keys` / :func:`redact_bitcoin_keys` — Bitcoin WIF keys and
  BIP-32 extended private keys (xprv, yprv, zprv, tprv…), verified by their checksum;
* :func:`scan_solana_keys` — the Solana check with the candidates it had no budget for;
* :func:`misdirected_exchange_keys` — an exchange's API key header sent to a
  site that is not that exchange;
* :func:`scan_own_keys` / :class:`OwnKeyScan` / :func:`own_keys_in` / :func:`address_of`
  / :func:`redact_own_keys` — raw Ethereum private keys that open one of the operator's
  listed addresses (read through :func:`read_listed_addresses_from`, handed in by the shield
  that owns the setting); :func:`checksum_address` — an address's EIP-55 spelling;
* :func:`protocol_contract` / :func:`router_match` / :class:`RouterMatch` — well-known
  exchange routers and the chains they are routers on (never a drainer, never flagged there).
"""

from .seed_phrase import MARKER as SEED_PHRASE_MARKER
from .seed_phrase import (SeedPhraseRun, find_seed_phrase_runs, phrase_from_entropy, redact_seed_phrases,
                          seed_phrase_spans, wordlist_ready)
from .solana_key import MARKER as SOLANA_KEY_MARKER
from .solana_key import find_solana_secret_keys, is_solana_secret_key, redact_solana_keys, scan_solana_keys
from .bitcoin_key import find_bitcoin_private_keys, redact_bitcoin_keys
from .evm_key import (OwnKeyScan, address_of, checksum_address, own_keys_in, read_listed_addresses_from,
                      redact_own_keys, scan_own_keys)
from . import exchange_keys, text_view
from .exchange_keys import misdirected_exchange_keys
from .known_contracts import RouterMatch, protocol_contract, router_match

__all__ = [
           "SEED_PHRASE_MARKER",
           "SOLANA_KEY_MARKER",
           "OwnKeyScan",
           "RouterMatch",
           "SeedPhraseRun",
           "address_of",
           "checksum_address",
           "exchange_keys",
           "find_bitcoin_private_keys",
           "find_seed_phrase_runs",
           "find_solana_secret_keys",
           "is_solana_secret_key",
           "misdirected_exchange_keys",
           "own_keys_in",
           "phrase_from_entropy",
           "protocol_contract",
           "read_listed_addresses_from",
           "redact_bitcoin_keys",
           "redact_own_keys",
           "redact_seed_phrases",
           "redact_solana_keys",
           "router_match",
           "scan_own_keys",
           "scan_solana_keys",
           "seed_phrase_spans",
           "text_view",
           "wordlist_ready",
]
