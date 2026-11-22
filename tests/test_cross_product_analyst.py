"""Tests for the cross-product analyst with a scripted fake model."""

import io
import json
from pathlib import Path

import pytest

import ingest
import report_tools as rt
from agents.nodes.cross_product_analyst import make_cross_product_analyst
from agents.prompt_loader import PROMPTS_DIR
from tests.fakes import FakeChatModel

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    assert ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    return db


@pytest.fixture(autouse=True)
def db(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


def output(function, params, key, path, value, statement="s"):
    return {"statement": statement, "values": {key: value},
            "source": {"function": function, "params": params, "key_paths": {key: path}}}


def test_findings_are_all_products_and_scope_is_enforced(tmp_path):
    total = rt.compare_years(2026)["value"]["pct_change"]
    edr = rt.compare_years(2026, product="EDR")["value"]["pct_change"]
    llm = FakeChatModel([
        [("compare_years", {"year": 2026})],
        {"findings": [output("compare_years", {"year": 2026}, "pct", "value.pct_change", total),
                      output("compare_years", {"year": 2026, "product": "EDR"}, "pct", "value.pct_change", edr)]},
    ])
    out = make_cross_product_analyst(llm)({"year": 2026, "run_dir": str(tmp_path)})
    assert [(d.product, d.source.params) for d in out["drafts"]] == [("ALL", {"year": 2026})]
    dropped = json.loads((tmp_path / "analyst_cross_product_dropped.json").read_text())
    assert "may only cite calls with product=None" in dropped[0]["problems"][0]
    assert (tmp_path / "analyst_cross_product_transcript.json").exists()


def test_prompt_and_task(tmp_path):
    llm = FakeChatModel([{"findings": []}, {"findings": []}])
    make_cross_product_analyst(llm)({"year": 2026, "run_dir": str(tmp_path)})
    system, human = llm.calls[0][0].content, llm.calls[0][1].content
    assert "all products together" in system and "Leave `product` out" in system and "$" not in system
    assert "year=2026" in system and "compared with 2025" in system
    assert human == "Analyse all products together for 2026."
    assert len(llm.bound_tools) == len(rt.TOOLS)


def test_prompt_differs_from_the_product_analyst_only_in_scope():
    """The cross-product prompt is the product analyst's prompt with the scope changed."""
    a = (PROMPTS_DIR / "analyst.md").read_text(encoding="utf-8")
    c = (PROMPTS_DIR / "cross_product_analyst.md").read_text(encoding="utf-8")
    assert a.split("## 2. Decide what is significant", 1)[1] == c.split("## 2. Decide what is significant", 1)[1]
