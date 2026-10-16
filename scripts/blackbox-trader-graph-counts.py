#!/usr/bin/env python3
"""What Umanitek's verified threat graph knows about crypto — the dated, repeatable count.

Writes ``plugins/blackbox/shields/trader/graph.json``, which the Trader Shield page
(``/shields/trader``) shows. Re-run it to refresh the numbers (the weekly figure):
the queries are fixed here, so two runs a week apart count the same way, and the
file records when and against what it was counted.

Run it ONLY against a test node's local store (a bench), never a production node:
these are whole-graph summaries — seconds to a minute of work for the store — and a
production node serves other people. It sends read-only SELECT queries and nothing else.

Usage::

    python3 scripts/blackbox-trader-graph-counts.py --store http://127.0.0.1:7878/query \\
        --node "bench test node bb-trader-1" [--out path/to/graph.json]

Standard library only, so it runs on a bench without the plugin's environment.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.parse
import urllib.request
from typing import Dict, List

PREFIXES = ("PREFIX defender: <urn:defender:> PREFIX dp: <urn:defender:p:> "
            "PREFIX schema: <http://schema.org/> ")
#: Only the verified graph (Umanitek's curated context graph), never community data.
IN_VERIFIED = 'FILTER(CONTAINS(STR(?g), "/agent-blackbox-vm/"))'
#: Brands whose look-alike sites a trader would meet. Names that are also everyday words
#: (scroll, blast, linea, eigen…) are left out: they would count sites that only share a word.
BRANDS = ("metamask", "phantom", "trustwallet", "coinbase", "binance", "okx", "bybit", "kraken", "ledger",
          "trezor", "exodus", "rabby", "walletconnect", "uniswap", "opensea", "pancakeswap", "raydium",
          "hyperliquid", "polymarket", "magiceden", "arbitrum", "solana", "etherscan", "layerzero", "zksync")
LURES = ("claim", "airdrop")
#: A package named for crypto: whole name parts only (so "electron" is not "tron", "undefined" not "defi").
PACKAGE_NAME = (r"(^|[-_.@/])(wallet|crypto|solana|ethers|web3|metamask|phantom|bitcoin|btc|binance|coinbase|"
                r"polymarket|hyperliquid|uniswap|defi|bip39|mnemonic|ledgerhq|trezor|tronweb|pancakeswap|opensea|"
                r"airdrop|blockchain|solidity|hardhat|raydium|pumpfun|pump-fun|nft|token|ethereum|eth)([-_.]|$|js|py|s)")
#: …or an advisory that says the package goes after wallets or keys.
PACKAGE_ADVISORY = (r"wallet|private key|seed phrase|mnemonic|crypto ?currency|metamask|phantom|exodus|solana|"
                    r"ethereum|bitcoin|clipper|drain")
STEALER_TAGS = (r"steal|vidar|lumma|redline|atomic|amos|raccoon|rhadamanth|arkei|clipper|clipbanker|cryptbot|"
                r"meduza|poseidon|banshee|risepro")


def _values(words) -> str:
    return " ".join(f'"{word}"' for word in words)


QUERIES: dict[str, str] = {
    "indicators_by_type": f"""SELECT ?type (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:iocType ?type }} {IN_VERIFIED} }} GROUP BY ?type""",
    "crypto_by_source": f"""SELECT ?type ?source (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:family "crypto" ; dp:iocType ?type ; dp:source ?source }}
        {IN_VERIFIED} }} GROUP BY ?type ?source""",
    "brand_sites": f"""SELECT ?brand (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        VALUES ?brand {{ {_values(BRANDS + LURES)} }}
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:iocType ?type ; dp:value ?v }}
        FILTER(?type IN ("domain", "url")) {IN_VERIFIED} FILTER(CONTAINS(LCASE(?v), ?brand)) }} GROUP BY ?brand""",
    "brand_sites_any": f"""SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        VALUES ?brand {{ {_values(BRANDS)} }}
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:iocType ?type ; dp:value ?v }}
        FILTER(?type IN ("domain", "url")) {IN_VERIFIED} FILTER(CONTAINS(LCASE(?v), ?brand)) }}""",
    "crypto_packages": f"""SELECT ?ecosystem (COUNT(DISTINCT ?package) AS ?n) (COUNT(DISTINCT ?t) AS ?versions) WHERE {{
        GRAPH ?g {{ ?t a defender:DependencySignal ; dp:package ?package ; dp:ecosystem ?ecosystem .
                    OPTIONAL {{ ?t schema:description ?d }} }} {IN_VERIFIED}
        FILTER(REGEX(LCASE(?package), "{PACKAGE_NAME}") || (BOUND(?d) && REGEX(LCASE(?d), "{PACKAGE_ADVISORY}"))) }}
        GROUP BY ?ecosystem""",
    "stealer_families": f"""SELECT ?tag (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:tag ?tag }} {IN_VERIFIED}
        FILTER(REGEX(?tag, "{STEALER_TAGS}", "i")) }} GROUP BY ?tag""",
    "wallet_values": f"""SELECT DISTINCT ?v WHERE {{
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:iocType "wallet" ; dp:value ?v }} {IN_VERIFIED} }}""",
    "coin_miners": f"""SELECT (COUNT(DISTINCT ?t) AS ?n) WHERE {{
        GRAPH ?g {{ ?t a defender:IocSignal ; dp:tag "CoinMiner" }} {IN_VERIFIED} }}""",
    "crypto_skills": f"""SELECT ?name WHERE {{
        GRAPH ?g {{ ?t a defender:SkillSignal ; schema:name ?name . OPTIONAL {{ ?t schema:description ?d }} }}
        {IN_VERIFIED} FILTER(REGEX(LCASE(CONCAT(?name, " ", COALESCE(?d, ""))), "wallet|crypto|solidity|seed phrase")) }}""",
}


def _ask(store: str, query: str, timeout: float) -> list[dict[str, str]]:
    body = urllib.parse.urlencode({"query": PREFIXES + query}).encode("ascii")
    request = urllib.request.Request(store, data=body, headers={"Accept": "application/sparql-results+json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        rows = json.load(response)["results"]["bindings"]
    return [{key: cell["value"] for key, cell in row.items()} for row in rows]


def _known_routers() -> dict[str, str]:
    """The well-known exchange routers (plugins/blackbox/kernel/crypto_secrets/known_contracts.json)."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "blackbox", "kernel",
                        "crypto_secrets", "known_contracts.json")
    with open(path, encoding="utf-8-sig") as handle:
        return {address.lower(): entry["name"] for address, entry in json.load(handle)["contracts"].items()}


def _count(rows: list[dict[str, str]], key: str = "n") -> int:
    return sum(int(row.get(key, 0)) for row in rows)


def collect(store: str, timeout: float) -> dict[str, object]:
    """Every figure the page shows, from one run of :data:`QUERIES`."""
    got = {name: _ask(store, query, timeout) for name, query in QUERIES.items()}
    by_type = {row["type"]: int(row["n"]) for row in got["indicators_by_type"]}
    crypto = got["crypto_by_source"]
    drainer_domains = sum(int(r["n"]) for r in crypto if r["source"] == "ScamSniffer scam-database")
    brands = sorted(({"brand": r["brand"], "sites": int(r["n"])} for r in got["brand_sites"] if r["brand"] in BRANDS),
                    key=lambda item: -item["sites"])
    lures = {r["brand"]: int(r["n"]) for r in got["brand_sites"] if r["brand"] in LURES}
    packages = {r["ecosystem"]: {"packages": int(r["n"]), "versions": int(r["versions"])} for r in got["crypto_packages"]}
    routers = _known_routers()
    wallets = {row["v"].lower() for row in got["wallet_values"]}
    listed_routers = sorted(routers[address] for address in wallets if address in routers)
    stealers = sorted(({"family": r["tag"], "indicators": int(r["n"])} for r in got["stealer_families"]),
                      key=lambda item: -item["indicators"])
    return {
        "indicators_total": sum(by_type.values()),
        "indicators_by_type": by_type,
        "crypto_indicators": _count(crypto),
        "drainer_phishing_domains": drainer_domains,
        # Exchange routers the feed wrongly lists as wallets (KI-370) are not drainers: left out.
        "drainer_wallets": len(wallets) - len(listed_routers),
        "drainer_wallets_listed": len(wallets),
        "exchange_routers_listed_as_wallets": listed_routers,
        "drainer_wallet_networks": sorted({"EVM" if value.startswith("0x") else "other" for value in wallets}),
        "brand_sites_total": _count(got["brand_sites_any"]),
        "brand_sites": brands,
        "lure_sites": lures,
        "crypto_packages": packages,
        "crypto_packages_total": sum(item["packages"] for item in packages.values()),
        "stealer_families": stealers,
        "stealer_indicators": sum(item["indicators"] for item in stealers),
        "coin_miner_indicators": _count(got["coin_miners"]),
        "crypto_skills": sorted({row["name"] for row in got["crypto_skills"]}),
        "sources": sorted({r["source"] for r in crypto}),
    }


#: Where the figures go: Trader Shield's own folder, served at /shields/trader/graph.json.
DEFAULT_OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "blackbox", "shields",
                           "trader", "graph.json")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--store", required=True, help="SPARQL query URL of a TEST node's local store")
    parser.add_argument("--node", required=True, help="what was counted, as shown on the page (e.g. 'bench test node')")
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--timeout", type=float, default=300.0)
    args = parser.parse_args(argv)
    figures = collect(args.store, args.timeout)
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC")
    document = {"as_of": stamp, "counted_on": args.node, "script": "scripts/blackbox-trader-graph-counts.py", **figures}
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1)
        handle.write("\n")
    print(json.dumps({k: v for k, v in document.items() if not isinstance(v, (list, dict))}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
