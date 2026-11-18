"""Tests for the synthesizer (code checks, retry, rejection) and the outline
display at the approval pause. A scripted fake model is used."""

import json

import pytest

from agents.nodes.approve_outline import format_outline
from agents.nodes.synthesizer import check_outline, make_synthesizer, tidy
from agents.state import OUTLINE_SECTIONS, NormalizedFinding, Outline
from agents.structured import StructuredOutputError, complete
from tests.fakes import FakeChatModel


def nf(fid, statement, values, data_gap=False):
    return NormalizedFinding(id=fid, product="EDR", statement=statement, values=values, direction="up",
                             data_gap=data_gap, confidence=0.9,
                             source={"function": "attacks_blocked", "params": {"year": 2026},
                                     "key_paths": {k: "value" for k in values}})


FINDINGS = [
    nf("F-001", "Blocked attacks rose 12.5% year over year.", {"pct_change": 12.5}),
    nf("F-002", "A new malware family led the ranking.", {"family": "X", "volume": 500}),
    nf("F-003", "Source country share changed.", {"share_pct": 20.0}),
    nf("F-004", "Some malware names have no family mapping.", {"detections": 30}, data_gap=True),
    nf("F-005", "An unremarkable finding.", {"total": 7}),
]


def outline_dict(**changes) -> dict:
    data = {
        "thesis": "Attacks shifted toward new malware while blocking held steady.",
        "signature_metric": {"finding_id": "F-001", "value_key": "pct_change"},
        "themes": [
            {"title": "New malware", "summary": "A new family rose to the top.", "finding_ids": ["F-002"]},
            {"title": "More attacks", "summary": "Blocked attacks rose.", "finding_ids": ["F-001", "F-001"]},
            {"title": "Gaps", "summary": "Some names are unmapped.", "finding_ids": ["F-004"]},
        ],
        "sections": [
            {"id": "trends", "title": "My trends", "goal": "Show the shifts.", "finding_ids": ["F-001"]},
            {"id": "product_performance", "title": "Perf", "goal": "Show blocking.", "finding_ids": ["F-001"]},
            {"id": "top_malware", "title": "Malware", "goal": "Show the new family.",
             "finding_ids": ["F-002", "F-004", "F-002"]},
            {"id": "source_countries", "title": "Countries", "goal": "Show sources.", "finding_ids": ["F-003"]},
            {"id": "recommendations", "title": "Recs", "goal": "Act on new malware.", "finding_ids": ["F-002"]},
        ],
    }
    data.update(changes)
    return data


def problems(**changes):
    return check_outline(Outline(**outline_dict(**changes)), FINDINGS)


# --- code checks ------------------------------------------------------------------------------

def test_valid_outline_passes():
    assert problems() == []


def test_unknown_finding_ids():
    themes = outline_dict()["themes"]
    themes[0] = {**themes[0], "finding_ids": ["F-099"]}
    assert problems(themes=themes) == ["these finding IDs do not exist: F-099"]


@pytest.mark.parametrize("metric, expected", [
    ({"finding_id": "F-099", "value_key": "x"}, "signature metric: finding F-099 does not exist"),
    ({"finding_id": "F-001", "value_key": "pct"}, "has no value named 'pct'; its values are pct_change"),
    ({"finding_id": "F-002", "value_key": "family"}, "F-002.family is not a number"),
])
def test_signature_metric(metric, expected):
    found = problems(signature_metric=metric)
    assert any(expected in p for p in found), found


def test_thesis_must_be_one_sentence():
    assert problems(thesis="Attacks rose. Malware changed.") == ["the thesis must be one sentence"]
    assert problems(thesis="Attacks rose, e.g. in email, while blocking held.") == []


def test_no_numbers_in_text_the_synthesizer_writes():
    sections = outline_dict()["sections"]
    sections[0] = {**sections[0], "goal": "Show the 3 biggest shifts."}
    themes = outline_dict()["themes"]
    themes[1] = {**themes[1], "summary": "Blocked attacks rose 12.5%."}
    found = problems(thesis="In 2026 attacks rose 12.5% overall.", sections=sections, themes=themes)
    assert any(p.startswith("the thesis contains numbers (12.5%)") for p in found)
    assert any(p.startswith("theme 2 summary contains numbers (12.5%)") for p in found)
    assert any(p.startswith("the trends goal contains numbers (3)") for p in found)


def test_years_are_allowed():
    assert problems(thesis="Compared with 2025, attacks in 2026 shifted toward new malware.") == []


def test_tidy_dedupes_orders_and_sets_titles():
    outline = tidy(Outline(**outline_dict()))
    assert [s.id for s in outline.sections] == list(OUTLINE_SECTIONS)
    assert [s.title for s in outline.sections] == [
        "Product performance", "Top malware", "Source countries", "Trends", "Recommendations"]
    assert outline.sections[1].finding_ids == ["F-002", "F-004"]
    assert outline.themes[1].finding_ids == ["F-001"]


def test_check_failure_gets_one_retry_with_the_problems():
    llm = FakeChatModel([outline_dict()])
    messages = []
    bad = outline_dict(thesis="Attacks rose 12.5%. Malware changed.")
    from langchain_core.messages import AIMessage
    out = complete(llm, messages, Outline, reply=AIMessage(content=json.dumps(bad)),
                   check=lambda o: check_outline(o, FINDINGS))
    assert out.thesis == outline_dict()["thesis"]
    assert "failed these checks" in messages[0].content
    assert "one sentence" in messages[0].content and "contains numbers" in messages[0].content


# --- the node --------------------------------------------------------------------------------------

def test_synthesizer_node(tmp_path):
    llm = FakeChatModel([outline_dict()])
    out = make_synthesizer(llm)({"normalized": FINDINGS, "year": 2026, "run_dir": str(tmp_path)})
    outline = out["outline"]
    assert [s.id for s in outline.sections] == list(OUTLINE_SECTIONS)
    saved = json.loads((tmp_path / "outline_1.json").read_text(encoding="utf-8"))
    assert saved["thesis"] == outline.thesis
    system, human = llm.calls[0]
    assert "2026 compared with 2025" in system.content and "$" not in system.content
    sent = json.loads(human.content.split("\n", 1)[1])
    assert [f["id"] for f in sent] == [f.id for f in FINDINGS]
    assert "source" not in sent[0] and sent[3]["data_gap"] is True


def test_synthesizer_fails_after_two_bad_outlines(tmp_path):
    bad = outline_dict(signature_metric={"finding_id": "F-099", "value_key": "x"})
    llm = FakeChatModel([bad, bad])
    with pytest.raises(StructuredOutputError, match="Outline: invalid output after one retry"):
        make_synthesizer(llm)({"normalized": FINDINGS, "year": 2026, "run_dir": str(tmp_path)})
    assert not (tmp_path / "outline_1.json").exists()


def test_rejected_outline_is_sent_back_with_the_comment(tmp_path):
    first = Outline(**outline_dict())
    llm = FakeChatModel([outline_dict(thesis="New malware drove the year while blocking held steady.")])
    state = {"normalized": FINDINGS, "year": 2026, "run_dir": str(tmp_path), "outline": first,
             "outline_feedback": "lead with the malware change"}
    out = make_synthesizer(llm)(state)
    human = llm.calls[0][1].content
    assert "rejected your previous outline" in human and first.thesis in human
    assert "Reviewer's comment: lead with the malware change" in human
    assert out["outline"].thesis.startswith("New malware")


def test_no_findings():
    with pytest.raises(ValueError, match="no findings"):
        make_synthesizer(FakeChatModel([]))({"normalized": [], "year": 2026, "run_dir": "."})


# --- the outline at the approval pause -------------------------------------------------------------

def test_format_outline():
    text = format_outline(tidy(Outline(**outline_dict())), FINDINGS)
    assert "Thesis: Attacks shifted toward new malware" in text
    assert "Signature metric: pct_change = 12.5  (F-001: Blocked attacks rose 12.5% year over year.)" in text
    assert "1. New malware" in text and "A new family rose to the top." in text
    # each section with its findings' statements, in report order
    perf, malware = text.index("  Product performance"), text.index("  Top malware")
    assert perf < malware < text.index("  Source countries") < text.index("  Trends")
    assert "Goal: Show the new family." in text
    assert "- F-002  A new malware family led the ranking." in text
    assert "- F-004  Some malware names have no family mapping. [data gap]" in text
    # unused findings and data gaps are listed
    unused = text.split("NOT USED IN ANY SECTION", 1)[1].split("DATA GAPS", 1)[0]
    assert "F-005  An unremarkable finding." in unused and "F-001" not in unused
    assert "F-004" in text.split("DATA GAPS", 1)[1]


def test_format_outline_wraps_long_statements():
    long = nf("F-001", "word " * 60, {"pct_change": 1.0})
    text = format_outline(Outline(**outline_dict()), [long, *FINDINGS[1:]])
    assert max(len(line) for line in text.splitlines()) <= 100
