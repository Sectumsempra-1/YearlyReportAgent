"""Tests for the code-only parts of the nodes (no model involved)."""

import io
from pathlib import Path

import pytest

import ingest
from agents.nodes.assemble import remove_tags
from agents.finding_check import resolve
from agents.nodes.collect_findings import collect_findings, direction
from agents.state import FindingDraft, NormalizedFinding, Outline, OUTLINE_SECTIONS

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    assert ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    return db


@pytest.fixture
def db(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


# --- collect_findings ---------------------------------------------------------------------------------

def test_resolve_key_paths():
    result = {"value": {"rows": [{"share_pct": 20.0}], "total": 5}}
    assert resolve(result, "value.rows.0.share_pct") == 20.0
    assert resolve(result, "value.total") == 5


@pytest.mark.parametrize("value, key_paths, expected", [
    ({"current": 5, "previous": 4, "pct_change": 25.0}, {"x": "value.pct_change"}, "up"),
    ({"current": 3, "previous": 4, "pct_change": -25.0}, {"x": "value.pct_change"}, "down"),
    ({"current": 100, "previous": 100, "pct_change": 0.5}, {"x": "value.pct_change"}, "flat"),
    ({"current": 100, "previous": 101, "pct_change": -1.0}, {"x": "value.current"}, "flat"),
    ({"current": 5, "previous": 0, "pct_change": None}, {"x": "value.current"}, "new"),
    ({"rows": [{"volume": 9, "new_this_year": True}]}, {"x": "value.rows.0.volume"}, "new"),
    ({"rows": [{"volume": 9, "previous_volume": 3, "pct_change": 200.0, "new_this_year": False}]},
     {"x": "value.rows.0.volume"}, "up"),
    ({"current": 5, "previous": None, "pct_change": None}, {"x": "value.current"}, "flat"),
    (42, {"x": "value"}, "flat"),
])
def test_direction(value, key_paths, expected):
    assert direction({"value": value, "caveats": []}, key_paths) == expected


def draft(product, function, params, key_paths, values, statement="s"):
    return FindingDraft(product=product, statement=statement, values=values,
                        source={"function": function, "params": params, "key_paths": key_paths})


def test_collect_findings_assigns_ids_copies_caveats_and_drops_bad(db, tmp_path):
    drafts = [
        draft("ALL", "top_countries", {"year": 2026}, {"v": "value.total"}, {"v": 1}),
        draft("Firewall", "product_summary", {"year": 2026, "product": "Firewall"},
              {"v": "value.c2_traffic.blocked"}, {"v": 1}),
        draft("EDR", "attacks_blocked", {"year": 2026, "product": "Nope"}, {"v": "value"}, {"v": 1}),
        draft("EDR", "compare_years", {"year": 2026, "product": "EDR"}, {"v": "value.pct_change"}, {"v": 1}),
    ]
    out = collect_findings({"drafts": drafts, "run_dir": str(tmp_path)})["findings"]
    # products in order, cross-product last; the bad call is dropped
    assert [(f.id, f.product, f.source.function) for f in out] == [
        ("F-001", "EDR", "compare_years"), ("F-002", "Firewall", "product_summary"),
        ("F-003", "ALL", "top_countries")]
    assert any("only blocked events" in c for c in out[1].caveats)
    assert any("IP geolocation" in c for c in out[2].caveats)
    assert (tmp_path / "findings_dropped.json").exists()
    assert "unknown product 'Nope'" in (tmp_path / "findings_dropped.json").read_text()


# --- assembly ---------------------------------------------------------------------------------------------

def test_remove_tags():
    assert remove_tags("rose 12.4% [F-007] in 2026 [F-001, F-002].") == "rose 12.4% in 2026."
    assert remove_tags("no tags") == "no tags"
