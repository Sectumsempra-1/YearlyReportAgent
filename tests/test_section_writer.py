"""Tests for the section writer with a scripted fake model. No real model is called."""

import json

import pytest

from agents.nodes.section_writer import make_section_writer, tags_in, writer_message
from agents.state import NormalizedFinding, Section, VerificationError, VerificationResult
from agents.structured import StructuredOutputError
from tests.fakes import FakeChatModel


def nf(fid, statement, values, caveats=(), data_gap=False):
    return NormalizedFinding(id=fid, product="EDR", statement=statement, values=values, direction="up",
                             caveats=list(caveats), data_gap=data_gap, confidence=0.9,
                             attack_techniques=[{"technique_id": "T1003", "name": "OS Credential Dumping",
                                                 "confidence": 0.8}],
                             source={"function": "attacks_blocked", "params": {"year": 2026},
                                     "key_paths": {k: "value" for k in values}})


F1 = nf("F-001", "Blocked attacks rose.", {"pct_change": 12.5}, caveats=["May overcount."])
F2 = nf("F-002", "Names lack a mapping.", {"detections": 30}, data_gap=True)


def loop_state(**extra):
    return {"year": 2026, "run_dir": ".", "section_id": "trends", "title": "Trends",
            "goal": "Show the shifts.", "findings": [F1, F2], "attempt": 1, **extra}


def test_writes_a_section(tmp_path):
    md = "Blocked attacks rose 12.5% [F-001], though totals may overcount.\n\nSome names lack a mapping [F-002]."
    llm = FakeChatModel([{"markdown": f"  {md}\n"}])
    out = make_section_writer(llm)(loop_state())
    assert out["draft"] == Section(id="trends", title="Trends", markdown=md, finding_ids_used=["F-001", "F-002"])


def test_writer_has_no_tools():
    llm = FakeChatModel([{"markdown": "Text [F-001]."}])
    make_section_writer(llm)(loop_state())
    assert llm.bound_tools is None


def test_writer_gets_its_section_and_only_its_findings():
    llm = FakeChatModel([{"markdown": "Text [F-001]."}])
    make_section_writer(llm)(loop_state())
    system, human = llm.calls[0]
    assert "2026, compared with 2025" in " ".join(system.content.split()) and "$" not in system.content
    assert human.content.startswith("Section: Trends\nGoal: Show the shifts.")
    sent = json.loads(human.content.split("Findings for this section:\n", 1)[1])
    assert [f["id"] for f in sent] == ["F-001", "F-002"]
    assert sent[0]["caveats"] == ["May overcount."] and sent[1]["data_gap"] is True
    assert sent[0]["techniques"] == ["T1003 OS Credential Dumping"]
    assert "source" not in sent[0]
    assert "previous draft" not in human.content


def test_rewrite_gets_previous_draft_and_errors():
    draft = Section(id="trends", title="Trends", markdown="Attacks rose 13% [F-001].")
    verification = VerificationResult(section_id="trends", passed=False, errors=[
        VerificationError(sentence="Attacks rose 13% [F-001].", problem="13% does not match F-001",
                          expected="12.5")])
    llm = FakeChatModel([{"markdown": "Attacks rose 12.5% [F-001]."}])
    make_section_writer(llm)(loop_state(attempt=2, draft=draft, verification=verification))
    human = llm.calls[0][1].content
    assert "Your previous draft failed verification:\nAttacks rose 13% [F-001]." in human
    assert "- 13% does not match F-001 (in: 'Attacks rose 13% [F-001].'); expected: 12.5" in human


def test_invalid_output_retries_once_then_fails():
    llm = FakeChatModel(["not json", {"markdown": ""}])
    with pytest.raises(StructuredOutputError, match="WriterOutput"):
        make_section_writer(llm)(loop_state())
    assert len(llm.calls) == 2


def test_tags_in():
    text = "a 1 [F-002] b 2 [F-001] c 3 [F-002] d [F-003, F-004] e [F-1] f F-005"
    assert tags_in(text) == ["F-002", "F-001", "F-003", "F-004"]


def test_message_without_verification_has_no_rewrite_part():
    assert "failed verification" not in writer_message(loop_state(
        verification=VerificationResult(section_id="trends", passed=True)))


@pytest.mark.parametrize("markdown, expected", [
    ("### Trends\n\nText [F-001].", "Text [F-001]."),
    ("## trends\nText [F-001].", "Text [F-001]."),
    ("### Monthly pattern\n\nText [F-001].", "### Monthly pattern\n\nText [F-001]."),
    ("Text [F-001].", "Text [F-001]."),
])
def test_repeated_title_heading_is_removed(markdown, expected):
    llm = FakeChatModel([{"markdown": markdown}])
    assert make_section_writer(llm)(loop_state())["draft"].markdown == expected
