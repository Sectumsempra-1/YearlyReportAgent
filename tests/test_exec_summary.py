"""Tests for the executive summary node with a scripted fake model."""

import json

import pytest

from agents.nodes.exec_summary import build_markdown, check_summary, make_exec_summary, summary_message
from agents.state import NormalizedFinding, Outline, Section, VerificationError, VerificationResult
from agents.structured import StructuredOutputError
from tests.fakes import FakeChatModel


def nf(fid, statement, values, caveats=()):
    return NormalizedFinding(id=fid, product="EDR", statement=statement, values=values, direction="up",
                             caveats=list(caveats), confidence=0.9,
                             source={"function": "attacks_blocked", "params": {"year": 2026},
                                     "key_paths": {k: "value" for k in values}})


FINDINGS = [nf("F-001", "Rose.", {"pct": 12.5}, caveats=["May overcount."]), nf("F-002", "New family.", {"v": 3})]
OUTLINE = Outline(
    thesis="Threats shifted toward credential theft.",
    signature_metric={"finding_id": "F-001", "value_key": "pct"},
    themes=[{"title": f"Theme {n}", "summary": f"Summary {n}.", "finding_ids": ["F-001"]} for n in (1, 2, 3)],
    sections=[{"id": s, "title": s, "goal": "g", "finding_ids": ["F-001"]}
              for s in ("product_performance", "top_malware", "source_countries", "trends", "recommendations")])
SECTIONS = {"product_performance": Section(id="product_performance", title="Product performance",
                                           markdown="Blocked attacks rose 12.5% [F-001].", finding_ids_used=["F-001"]),
            "recommendations": Section(id="recommendations", title="Recommendations",
                                       markdown="- Act on it [F-001].", finding_ids_used=["F-001"])}

GOOD = {
    "thesis": "Threats shifted sharply toward credential theft.",
    "headlines": [f"Headline {n} rose 12.5% [F-001]." for n in range(5)],
    "theme_paragraphs": ["Paragraph one.", "Paragraph two.", "Paragraph three."],
    "recommendations": ["Act on credential theft [F-001].", "Watch the new family [F-002]."],
}


def state(**extra):
    return {"year": 2026, "run_dir": ".", "section_id": "executive_summary", "title": "Executive summary",
            "goal": "g", "outline": OUTLINE, "verified_sections": SECTIONS, "findings": FINDINGS,
            "attempt": 1, "feedback": "", **extra}


def test_builds_the_summary_in_a_fixed_structure():
    out = make_exec_summary(FakeChatModel([GOOD]))(state())["draft"]
    assert out.id == "executive_summary" and out.title == "Executive summary"
    md = out.markdown
    assert md.startswith("**Threats shifted sharply toward credential theft.**")
    order = [md.index(h) for h in ("### Headline numbers", "### Theme 1", "### Theme 2", "### Theme 3",
                                   "### Top recommendations")]
    assert order == sorted(order)
    assert md.count("- Headline") == 5
    assert "### Theme 2\n\nParagraph two." in md
    assert md.endswith("- Watch the new family [F-002].")
    assert out.finding_ids_used == ["F-001", "F-002"]


def test_has_no_tools():
    llm = FakeChatModel([GOOD])
    make_exec_summary(llm)(state())
    assert llm.bound_tools is None


def test_gets_outline_sections_and_findings():
    llm = FakeChatModel([GOOD])
    make_exec_summary(llm)(state())
    system, human = llm.calls[0]
    assert "for 2026, compared with 2025" in " ".join(system.content.split()) and "$" not in system.content
    text = human.content
    assert "Outline thesis: Threats shifted toward credential theft." in text
    assert "1. Theme 1: Summary 1. (findings F-001)" in text
    assert "## Product performance\nBlocked attacks rose 12.5% [F-001]." in text
    assert text.index("## Product performance") < text.index("## Recommendations")
    findings = json.loads(text.split("Findings used in the sections:\n", 1)[1].split("\n")[0])
    assert [f["id"] for f in findings] == ["F-001", "F-002"] and findings[0]["caveats"] == ["May overcount."]
    assert "rejected" not in text and "failed verification" not in text


@pytest.mark.parametrize("change, problem", [
    ({"headlines": GOOD["headlines"][:4]}, "give 5 to 8 headlines, not 4"),
    ({"headlines": GOOD["headlines"] * 2}, "give 5 to 8 headlines, not 10"),
    ({"headlines": GOOD["headlines"][:4] + ["No number here [F-001]."]}, "headline 5 needs a number"),
    ({"headlines": GOOD["headlines"][:4] + ["Rose 12.5% without a tag."]}, "headline 5 needs a number"),
    ({"theme_paragraphs": ["Only one."]}, "give one paragraph per outline theme: 3 themes, 1 paragraphs"),
    ({"recommendations": []}, "give at least one recommendation"),
    ({"recommendations": ["Do something."]}, "recommendation 1 cites no finding"),
    ({"thesis": "Attacks rose 12.5% overall."}, "the thesis must not contain numbers"),
])
def test_structure_checks(change, problem):
    from agents.nodes.exec_summary import SummaryOutput
    problems = check_summary(SummaryOutput(**{**GOOD, **change}), OUTLINE.themes)
    assert any(p.startswith(problem) for p in problems), problems


def test_structure_problem_gets_one_retry():
    bad = {**GOOD, "headlines": GOOD["headlines"][:3]}
    llm = FakeChatModel([bad, GOOD])
    out = make_exec_summary(llm)(state())["draft"]
    assert out.markdown.count("- Headline") == 5
    assert "give 5 to 8 headlines, not 3" in llm.calls[1][-1].content


def test_fails_after_two_bad_answers():
    bad = {**GOOD, "recommendations": []}
    with pytest.raises(StructuredOutputError, match="SummaryOutput"):
        make_exec_summary(FakeChatModel([bad, bad]))(state())


def test_rejected_report_sends_the_previous_summary_and_comment():
    previous = Section(id="executive_summary", title="Executive summary", markdown="Old summary [F-001].")
    text = summary_message(state(feedback="lead with the new family", draft=previous))
    assert "A reviewer rejected your previous summary:\nOld summary [F-001]." in text
    assert "Reviewer's comment: lead with the new family" in text


def test_failed_verification_sends_the_errors():
    previous = Section(id="executive_summary", title="Executive summary", markdown="Rose 13% [F-001].")
    verification = VerificationResult(section_id="executive_summary", passed=False, errors=[
        VerificationError(sentence="Rose 13% [F-001].", problem="13% quotes F-001 differently", expected="12.5%")])
    text = summary_message(state(draft=previous, verification=verification))
    assert "Your previous draft failed verification:\nRose 13% [F-001]." in text
    assert "- 13% quotes F-001 differently (in: 'Rose 13% [F-001].'); expected: 12.5%" in text
    assert "rejected your previous summary" not in text


def test_build_markdown_uses_outline_titles():
    from agents.nodes.exec_summary import SummaryOutput
    md = build_markdown(SummaryOutput(**GOOD), OUTLINE.themes)
    assert [line for line in md.splitlines() if line.startswith("### ")] == [
        "### Headline numbers", "### Theme 1", "### Theme 2", "### Theme 3", "### Top recommendations"]
