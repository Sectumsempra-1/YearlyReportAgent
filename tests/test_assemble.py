"""Tests for the final assembly (SPEC 7.7): the methodology section, its
verification, and report.md / report_clean.md."""

import io
import json
from pathlib import Path

import pytest

import ingest
import report_tools as rt
from agents.nodes.assemble import assemble, build_methodology, remove_tags, tag_numbers
from agents.state import NormalizedFinding, REPORT_ORDER, SECTION_TITLES, Section

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


def unmapped_gap(fid="F-003"):
    row = rt.unmapped_malware(2026, product="EDR")["value"]["rows"][0]
    return NormalizedFinding(
        id=fid, product="EDR", statement=f"{row['vendor_name']} has no family mapping, with "
                                         f"{row['detections']} detections in 2026.",
        values={"detections": row["detections"]}, direction="flat", data_gap=True, confidence=0.5,
        source={"function": "unmapped_malware", "params": {"year": 2026, "product": "EDR"},
                "key_paths": {"detections": "value.rows.0.detections"}})


def used_finding():
    result = rt.top_countries(2026)
    return NormalizedFinding(
        id="F-001", product="ALL", statement="s", values={"share": result["value"]["rows"][0]["share_pct"]},
        direction="up", caveats=result["caveats"], confidence=0.9,
        attack_techniques=[{"technique_id": "T1110", "name": "Brute Force", "confidence": 0.8}],
        source={"function": "top_countries", "params": {"year": 2026}, "key_paths": {"share": "value.rows.0.share_pct"}})


def sections(**markdown):
    out = {sid: Section(id=sid, title=SECTION_TITLES[sid], markdown=f"Text for {sid}.")
           for sid in REPORT_ORDER if sid != "methodology"}
    for sid, md in markdown.items():
        out[sid] = Section(id=sid, title=SECTION_TITLES[sid], markdown=md,
                           finding_ids_used=["F-001"] if "[F-001]" in md else [])
    return out


def report_state(tmp_path, findings=None, **section_markdown):
    return {"year": 2026, "run_dir": str(tmp_path), "normalized": findings or [used_finding(), unmapped_gap()],
            "sections": sections(**section_markdown)}


# --- methodology ----------------------------------------------------------------------------------

def test_tag_numbers():
    gap = unmapped_gap()
    tagged = tag_numbers(gap.statement, gap)
    assert f"{gap.values['detections']} [F-003] detections in 2026" in tagged
    assert "2026 [F-003]" not in tagged   # years are not values


def test_methodology_content(tmp_path):
    state = report_state(tmp_path, trends="Share was high [F-001].")
    md = build_methodology(state).markdown
    assert "covers 2026 compared with 2025" in md
    for p in rt.list_products()["value"]:
        assert f"- {p['product']} ({p['category']}): 2025 and 2026" in md
    assert "`top_countries`" in md                     # the queries behind the report's findings
    for caveat in used_finding().caveats:              # rule 6: the caveats reach the report
        assert f"- {caveat}" in md
    assert "MITRE ATT&CK for Enterprise v20.1" in md and "- T1110 Brute Force" in md
    gap = unmapped_gap()
    assert f"- {tag_numbers(gap.statement, gap)} [F-003]" in md   # rule 5: gaps are listed


def test_unused_findings_add_no_caveats_but_all_gaps_are_listed(tmp_path):
    md = build_methodology(report_state(tmp_path)).markdown   # no section cites F-001
    assert "IP geolocation" not in md and "- None." in md
    assert "[F-003]" in md                                      # the gap is listed although unused


def test_no_gaps(tmp_path):
    md = build_methodology(report_state(tmp_path, findings=[used_finding()])).markdown
    assert "- None reported." in md


# --- assemble -----------------------------------------------------------------------------------------

def test_assemble_writes_both_reports_in_order(tmp_path):
    out = assemble(report_state(tmp_path, trends="Share was 1.0% [F-001]."))
    assert out["status"] == "completed"
    report = (tmp_path / "report.md").read_text(encoding="utf-8")
    assert report.startswith("# Yearly security report 2026\n\nCompared with 2025.")
    positions = [report.index(f"## {SECTION_TITLES[sid]}") for sid in REPORT_ORDER]
    assert positions == sorted(positions)
    assert "[F-003]" in report and "[F-001]" in report
    clean = (tmp_path / "report_clean.md").read_text(encoding="utf-8")
    assert "[F-" not in clean and clean == remove_tags(report)
    assert json.loads((tmp_path / "verify_methodology.json").read_text())["passed"]
    assert (tmp_path / "section_methodology.json").exists()


def test_methodology_that_fails_verification_writes_no_report(tmp_path):
    gap = unmapped_gap()
    bad = gap.model_copy(update={"statement": gap.statement + " About 7 names are affected."})
    out = assemble(report_state(tmp_path, findings=[used_finding(), bad]))
    assert out["status"] == "failed"
    assert not (tmp_path / "report.md").exists()
    failures = json.loads((tmp_path / "failures.json").read_text())
    assert "has no finding tag directly after it" in failures["methodology"]["errors"][0]["problem"]


def test_missing_section_is_an_error(tmp_path):
    state = report_state(tmp_path)
    del state["sections"]["trends"]
    with pytest.raises(ValueError, match="missing sections"):
        assemble(state)
