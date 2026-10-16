"""Shield boundary guard: the shared packages never name Trader Shield's parts again.

Trader Shield lives in ``plugins/blackbox/shields/``; the kernel, detection, the
guard and the dashboard reach it only through the shields registry. The names its
parts had before they moved there (``wallet_mode``, ``wallet_files``, the wallet
tables, the dashboard's ``protection`` module…) must not come back into those four
packages — a re-introduced name is a second copy of shield code outside its module.

The walk reads CODE, not prose: in Python every identifier the AST holds (names,
attributes, imports, definitions, parameters, keyword arguments); in JavaScript
(``.js`` files and inline ``<script>`` blocks) every word left once comments and
string literals are removed. Docstrings, comments and strings are prose and may
still name a wallet — the seed-phrase docstring in ``detection/content_scanners.py``
does, and the ``/api/agents/protection`` route is a URL, not a module.

Stdlib only; reads source text, never imports the plugin.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[2] / "plugins" / "blackbox"
SHARED_PACKAGES = ("kernel", "detection", "guard", "dashboard")

RETIRED_IDENTIFIERS = frozenset({
    "wallet_mode", "wallet_files", "app_wallets", "firefox_extensions", "found_wallets",
    "protection", "SUPPORTED_WALLETS", "PLANNED_WALLETS", "WALLET_SECRET_IDENTIFIERS",
    "belongs_to_mode", "ANY_EXTENSION_WALLET", "_own_key_findings", "APP_WALLETS",
    "WALLET_LOGOS",
})

_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
_JS_WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")


def python_identifiers(source: str) -> set[str]:
    """Every identifier a Python module's code uses; strings and comments are not code."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            found.add(node.name)
        elif isinstance(node, (ast.arg, ast.keyword)) and node.arg:
            found.add(node.arg)
        elif isinstance(node, ast.alias):
            found.update(node.name.split("."))
            if node.asname:
                found.add(node.asname)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.update(node.module.split("."))
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            found.update(node.names)
    return found


def _starts_regex(kept: list[str]) -> bool:
    """Whether a ``/`` here opens a regex literal: no value precedes it (an operator,
    an opening bracket or ``return`` does), so it cannot be division."""
    before = "".join(kept[-12:]).rstrip()
    return not before or before[-1] in "(,=:[!&|?{};+-*%<>~^" or re.search(r"\breturn$", before) is not None


def _skip_regex(source: str, index: int) -> int:
    """The index just past a regex literal opening at ``source[index]`` (a ``/``)."""
    index += 1
    in_class = False
    while index < len(source) and source[index] != "\n":
        char = source[index]
        if char == "\\":
            index += 2
            continue
        if char == "[":
            in_class = True
        elif char == "]":
            in_class = False
        elif char == "/" and not in_class:
            return index + 1
        index += 1
    return index


def _strip_js_prose(source: str) -> str:
    """JavaScript with its comments, string literals and regex literals blanked out.

    A one-pass scanner, enough for the dashboard's hand-written code (a regex literal
    holding a quote, ``/"/g``, would otherwise open a string); a template literal is
    dropped whole, ``${…}`` included.
    """
    kept: list[str] = []
    index, length = 0, len(source)
    while index < length:
        char, pair = source[index], source[index:index + 2]
        if pair == "//":
            end = source.find("\n", index)
            index = length if end < 0 else end
        elif pair == "/*":
            end = source.find("*/", index + 2)
            index = length if end < 0 else end + 2
        elif char == "/" and _starts_regex(kept):
            index = _skip_regex(source, index)
            kept.append(" ")
        elif char in "'\"`":
            index += 1
            while index < length and source[index] != char:
                index += 2 if source[index] == "\\" else 1
            index += 1
            kept.append(" ")
        else:
            kept.append(char)
            index += 1
    return "".join(kept)


def javascript_identifiers(source: str) -> set[str]:
    """Every word JavaScript code uses once its comments and strings are removed."""
    return set(_JS_WORD.findall(_strip_js_prose(source)))


def _identifiers_in(path: Path) -> set[str]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".py":
        return python_identifiers(text)
    if path.suffix == ".js":
        return javascript_identifiers(text)
    return set().union(*(javascript_identifiers(block) for block in _INLINE_SCRIPT.findall(text)))


def _code_files() -> list[Path]:
    files: list[Path] = []
    for package in SHARED_PACKAGES:
        for path in sorted((PLUGIN / package).rglob("*")):
            if path.suffix not in {".py", ".js", ".html"} or "__pycache__" in path.parts:
                continue
            if "vendor" in path.relative_to(PLUGIN).parts:   # third-party bundles, not our code
                continue
            files.append(path)
    return files


def test_the_shared_packages_name_no_retired_shield_identifier():
    offenders = {
        str(path.relative_to(PLUGIN)): sorted(hits)
        for path in _code_files()
        if (hits := _identifiers_in(path) & RETIRED_IDENTIFIERS)
    }
    assert not offenders, (
        "shield code belongs in plugins/blackbox/shields/ and is reached through the registry; "
        f"these files name its retired parts: {offenders}"
    )


def test_the_walk_covers_every_shared_package_and_the_dashboard_script():
    walked = {path.relative_to(PLUGIN).parts[0] for path in _code_files()}
    assert walked == set(SHARED_PACKAGES)
    names = {str(path.relative_to(PLUGIN)) for path in _code_files()}
    assert {"dashboard/static/index.html", "dashboard/static/shields.js"} <= names


def test_python_code_is_caught_and_python_prose_is_not():
    code = (
        "from ..shields.trader import wallet_mode\n"
        "import plugins.blackbox.detection.wallet_files as moved\n"
        "x = shields.APP_WALLETS\n"
        "def belongs_to_mode(found_wallets, *, protection=None):\n"
        "    return call(_own_key_findings=1)\n"
    )
    assert {"wallet_mode", "wallet_files", "APP_WALLETS", "belongs_to_mode", "found_wallets",
            "protection", "_own_key_findings"} <= python_identifiers(code)
    prose = (
        '"""MetaMask and wallet_mode are named here only in prose."""\n'
        "# wallet_files was the old module\n"
        'ROUTE = "/api/agents/protection"\n'
    )
    assert not python_identifiers(prose) & RETIRED_IDENTIFIERS


def test_javascript_code_is_caught_and_javascript_prose_is_not():
    assert {"WALLET_LOGOS", "SUPPORTED_WALLETS"} <= javascript_identifiers(
        "var logo = WALLET_LOGOS[id]; if (SUPPORTED_WALLETS.indexOf(id) < 0) return;"
    )
    prose = (
        "// protection mode segmented control\n"
        "/* WALLET_LOGOS lived here */\n"
        'postJSON("/api/agents/protection", {});\n'
        "var label = 'found_wallets' + `wallet_mode ${x}`;\n"
    )
    assert not javascript_identifiers(prose) & RETIRED_IDENTIFIERS
    # a quote inside a regex literal does not open a string that hides the code after it
    after_regex = 's.replace(/"/g, "&quot;").replace(/\'/g, "&#39;");\nvar w = APP_WALLETS;\n'
    assert "APP_WALLETS" in javascript_identifiers(after_regex)
    assert "APP_WALLETS" in javascript_identifiers("var r = a / b; var c = d / e; APP_WALLETS();")


def test_every_function_the_dashboard_script_declares_is_walked():
    """The scanner stays in step over the real files: no declared function is swallowed."""
    for path in _code_files():
        if path.suffix == ".py":
            continue
        text = path.read_text(encoding="utf-8")
        declared = set(re.findall(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(", text))
        missing = declared - _identifiers_in(path)
        assert not missing, f"{path.relative_to(PLUGIN)}: the scanner lost track before {sorted(missing)[:5]}"
