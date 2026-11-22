"""Rule 8 for every prompt in agents/prompts/: describe how to analyse and
write, never what the data contains."""

import csv
import re
from pathlib import Path

import pytest

from agents.prompt_loader import PROMPTS_DIR

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = sorted(PROMPTS_DIR.glob("*.md"))
MONTHS = ["January", "February", "March", "April", "June", "July", "August", "September",
          "October", "November", "December"]


def data_words() -> set[str]:
    """Products, malware aliases, families and vendor names that appear in data/."""
    words = set()
    with open(ROOT / "data" / "reference" / "products.csv", encoding="utf-8") as f:
        words |= {r["product"] for r in csv.DictReader(f)}
    with open(ROOT / "data" / "reference" / "malware_aliases.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            words |= {r["alias"], r["canonical_family"]}
    for path in (ROOT / "data" / "exports").glob("*.csv"):
        with open(path, encoding="utf-8") as f:
            words |= {r["malware_name"] for r in csv.DictReader(f) if r["malware_name"]}
    return words


WORDS = sorted(data_words())


def test_there_are_prompts():
    assert {p.stem for p in PROMPTS} >= {"analyst", "normalizer"}


@pytest.mark.parametrize("path", PROMPTS, ids=lambda p: p.name)
def test_prompt_does_not_describe_the_data(path):
    text = path.read_text(encoding="utf-8")
    for word in WORDS:
        assert not re.search(rf"\b{re.escape(word)}\b", text, re.I), word
    assert not re.search(r"\b20\d\d\b", text), "years must come from placeholders"
    assert not re.search(r"\b\d+(\.\d+)?%", text), "no percentages"
    for month in MONTHS:
        assert month not in text, month
    for code in COUNTRIES:   # country codes that occur in the data, as standalone words
        assert not re.search(rf"\b{code}\b", text), code


def data_countries() -> set[str]:
    codes = set()
    for path in (ROOT / "data" / "exports").glob("*.csv"):
        with open(path, encoding="utf-8") as f:
            codes |= {r["source_country"] for r in csv.DictReader(f)}
    return codes


COUNTRIES = sorted(data_countries())


@pytest.fixture(scope="module")
def data_numbers(tmp_path_factory):
    """Every distinctive number the tools return for the loaded data: decimals >= 10, integers >= 100."""
    import io
    import os

    import ingest
    import report_tools as rt
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    assert ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    old = os.environ.get("REPORT_DB")
    os.environ["REPORT_DB"] = str(db)
    numbers = set()

    def walk(node):
        if isinstance(node, dict):
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
        elif isinstance(node, float) and not node.is_integer() and abs(node) >= 10:
            numbers.add(f"{abs(node)}")   # small decimals (0.9, 1.5) are too common to mean anything
        elif isinstance(node, int) and not isinstance(node, bool) and node >= 100 and not 2000 <= node <= 2099:
            numbers.add(f"{node}")

    try:
        products = [p["product"] for p in rt.list_products()["value"]]
        for year in (2025, 2026):
            for scope in [None, *products]:
                for fn in (rt.compare_years, rt.attack_type_changes, rt.top_countries, rt.sector_breakdown,
                           rt.severity_breakdown, rt.monthly_series, rt.unmapped_malware):
                    walk(fn(year, product=scope)["value"])
                walk(rt.top_malware(year, n=50, product=scope)["value"])
            for p in products:
                walk(rt.product_summary(year, p)["value"])
    finally:
        if old is None:
            del os.environ["REPORT_DB"]
        else:
            os.environ["REPORT_DB"] = old
    return numbers


@pytest.mark.parametrize("path", PROMPTS, ids=lambda p: p.name)
def test_prompt_contains_no_number_from_the_data(path, data_numbers):
    text = path.read_text(encoding="utf-8")
    found = {m.group() for m in re.finditer(r"(?<![\w.])\d[\d,]*(?:\.\d+)?(?![\w.])", text)}
    leaked = {n for n in found if n.replace(",", "") in data_numbers}
    assert not leaked, f"numbers from the data in {path.name}: {sorted(leaked)}"
