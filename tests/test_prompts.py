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
    # no country codes or names as examples (two capital letters on their own)
    assert not re.search(r"\b(?:country|countries)\b[^.\n]*\b[A-Z]{2}\b", text)
