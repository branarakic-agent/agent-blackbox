"""What the verified graph knows about crypto: the counts the Trader Shield page shows.

The numbers come from scripts/blackbox-trader-graph-counts.py, run against a test node's
copy of the verified graph (never a production node) and saved with the date it ran. These
tests keep the saved file honest and the script safe to re-run each week.
"""

from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

from plugins.blackbox import shields
from plugins.blackbox.dashboard import shields_routes

REPO = Path(__file__).resolve().parents[2]
TRADER = shields.get("trader")
GRAPH = TRADER.folder / "graph.json"
COUNTS = json.loads(GRAPH.read_text(encoding="utf-8"))


def _script():
    spec = importlib.util.spec_from_file_location("graph_counts", REPO / "scripts" / "blackbox-trader-graph-counts.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_counts_say_when_and_where_they_were_counted():
    assert re.fullmatch(r"\d{4}-\d\d-\d\d \d\d:\d\d UTC", COUNTS["as_of"])
    assert COUNTS["counted_on"] and COUNTS["script"] == "scripts/blackbox-trader-graph-counts.py"


def test_the_counts_add_up():
    assert COUNTS["indicators_total"] == sum(COUNTS["indicators_by_type"].values())
    assert COUNTS["drainer_phishing_domains"] <= COUNTS["crypto_indicators"] <= COUNTS["indicators_total"]
    assert COUNTS["crypto_packages_total"] == sum(item["packages"] for item in COUNTS["crypto_packages"].values())
    assert COUNTS["stealer_indicators"] == sum(item["indicators"] for item in COUNTS["stealer_families"])
    assert COUNTS["brand_sites_total"] <= sum(item["sites"] for item in COUNTS["brand_sites"])
    # Exchange routers the feed lists as wallets are not counted as drainers (KI-370).
    assert COUNTS["drainer_wallets"] + len(COUNTS["exchange_routers_listed_as_wallets"]) == COUNTS["drainer_wallets_listed"]
    assert COUNTS["drainer_wallets_listed"] == COUNTS["indicators_by_type"].get("wallet", 0)
    assert COUNTS["drainer_wallet_networks"] == ["EVM"]


def test_every_query_only_reads_the_verified_graph():
    script = _script()
    for name, query in script.QUERIES.items():
        assert query.lstrip().upper().startswith("SELECT"), name                  # read-only
        assert "/agent-blackbox-vm/" in query, name                               # verified graph only
        assert not re.search(r"\b(INSERT|DELETE|LOAD|CLEAR|DROP|CREATE)\b", query, re.IGNORECASE), name


def test_the_package_pattern_does_not_count_words_that_only_contain_a_crypto_word():
    pattern = re.compile(_script().PACKAGE_NAME)
    for crypto in ("solana-web3-helper", "@scope/wallet-utils", "ethers", "web3", "crypto-wallet-utils", "bip39"):
        assert pattern.search(crypto), crypto
    for other in ("electron", "undefined-checker", "strongly-typed", "jupiter-planet-facts", "methane"):
        assert not pattern.search(other), other


def test_the_script_writes_the_file_the_shield_serves():
    assert Path(_script().DEFAULT_OUT).resolve() == GRAPH.resolve()


def test_the_page_shows_the_counts_it_is_served():
    page = TRADER.page.read_text(encoding="utf-8")
    assert 'getJSON("graph.json")' in page and 'id="known-stats"' in page


def test_the_dashboard_serves_the_counts():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    shields_routes.register_pages(app)
    response = TestClient(app).get("/shields/trader/graph.json")
    assert response.status_code == 200 and response.json()["as_of"] == COUNTS["as_of"]


def test_the_quick_start_ends_with_a_safe_test():
    page = TRADER.page.read_text(encoding="utf-8")
    steps = re.findall(r"<li><span><b>(.*?)</b>", page.split('class="qs"', 1)[1].split("</ol>", 1)[0])
    assert steps[0] == "Install Blackbox" and steps[-1] == "Try it safely."
