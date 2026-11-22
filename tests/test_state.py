"""Tests for the data contracts in agents/state.py."""

import pytest
from pydantic import ValidationError

from agents.state import (
    OUTLINE_SECTIONS, REPORT_ORDER, Approval, Finding, FindingDraft, NormalizedFinding, Outline,
    Section, Source, TechniqueMapping, VerificationResult, merge,
)

SOURCE = {"function": "compare_years", "params": {"year": 2026, "product": "EDR", "attack_type": None},
          "key_paths": {"pct_change": "value.pct_change"}}
DRAFT = {"product": "EDR", "statement": "Blocked attacks rose.", "values": {"pct_change": 12.5},
         "source": SOURCE}
FINDING = {**DRAFT, "id": "F-001", "direction": "up", "caveats": []}


def outline(**changes):
    data = {
        "thesis": "t",
        "signature_metric": {"finding_id": "F-001", "value_key": "pct_change"},
        "themes": [{"title": f"t{i}", "summary": "s", "finding_ids": ["F-001"]} for i in range(3)],
        "sections": [{"id": s, "title": s, "goal": "g", "finding_ids": ["F-001"]} for s in OUTLINE_SECTIONS],
    }
    data.update(changes)
    return Outline(**data)


def test_valid_models():
    FindingDraft(**DRAFT)
    Finding(**FINDING)
    NormalizedFinding(**FINDING, attack_techniques=[{"technique_id": "T1566.001", "confidence": 0.7}],
                      sector="Finance", severity="high", related_findings=["F-002"], confidence=0.9)
    assert outline().finding_ids() == {"F-001"}


def test_values_and_key_paths_must_match():
    with pytest.raises(ValidationError, match="same keys"):
        FindingDraft(**{**DRAFT, "values": {"other": 1}})


def test_unused_key_paths_are_dropped():
    source = {**SOURCE, "key_paths": {"pct_change": "value.pct_change", "rank": "value.rows.0.rank"}}
    f = FindingDraft(**{**DRAFT, "source": source})
    assert f.source.key_paths == {"pct_change": "value.pct_change"}


def test_source_function_must_be_a_tool():
    with pytest.raises(ValidationError):
        Source(**{**SOURCE, "function": "run_sql"})


@pytest.mark.parametrize("field, value", [
    ("id", "F-1"), ("id", "001"), ("direction", "sideways"),
])
def test_finding_fields(field, value):
    with pytest.raises(ValidationError):
        Finding(**{**FINDING, field: value})


def test_extra_fields_are_rejected():
    with pytest.raises(ValidationError):
        FindingDraft(**DRAFT, id="F-001")   # the model must not set code-only fields


@pytest.mark.parametrize("technique_id", ["T1566", "T1566.001"])
def test_valid_technique_ids(technique_id):
    TechniqueMapping(technique_id=technique_id, confidence=0.5)


@pytest.mark.parametrize("technique_id, confidence", [
    ("T156", 0.5), ("1566", 0.5), ("T1566.1", 0.5), ("T1566", 1.1), ("T1566", -0.1),
])
def test_invalid_technique_mappings(technique_id, confidence):
    with pytest.raises(ValidationError):
        TechniqueMapping(technique_id=technique_id, confidence=confidence)


@pytest.mark.parametrize("changes", [
    {"sector": "Retail"}, {"severity": "urgent"}, {"related_findings": ["X-1"]}, {"confidence": 2},
])
def test_invalid_normalized_finding(changes):
    with pytest.raises(ValidationError):
        NormalizedFinding(**{**FINDING, "confidence": 0.5, **changes})


def test_normalized_sector_and_severity_allow_unspecified():
    f = NormalizedFinding(**FINDING, confidence=0.5)
    assert (f.sector, f.severity) == ("unspecified", "unspecified")
    NormalizedFinding(**FINDING, confidence=0.5, sector="multiple")


@pytest.mark.parametrize("n", [2, 6])
def test_outline_needs_three_to_five_themes(n):
    themes = [{"title": "t", "summary": "s", "finding_ids": ["F-001"]}] * n
    with pytest.raises(ValidationError):
        outline(themes=themes)


def test_outline_needs_each_section_exactly_once():
    sections = [{"id": s, "title": s, "goal": "g", "finding_ids": ["F-001"]} for s in OUTLINE_SECTIONS]
    with pytest.raises(ValidationError, match="once each"):
        outline(sections=sections[:-1])
    with pytest.raises(ValidationError, match="once each"):
        outline(sections=sections + sections[:1])
    with pytest.raises(ValidationError):
        outline(sections=[{**sections[0], "finding_ids": []}] + sections[1:])


def test_outline_excludes_summary_and_methodology():
    assert "executive_summary" not in OUTLINE_SECTIONS and "methodology" not in OUTLINE_SECTIONS
    assert REPORT_ORDER[0] == "executive_summary" and REPORT_ORDER[-1] == "methodology"


def test_verification_passed_means_no_errors():
    VerificationResult(section_id="trends", passed=True)
    VerificationResult(section_id="trends", passed=False,
                       errors=[{"sentence": "s", "problem": "p", "expected": "1"}])
    with pytest.raises(ValidationError):
        VerificationResult(section_id="trends", passed=False)
    with pytest.raises(ValidationError):
        VerificationResult(section_id="trends", passed=True, errors=[{"sentence": "s", "problem": "p"}])


def test_approval():
    Approval(step="outline", decision="reject", comment="c")
    with pytest.raises(ValidationError):
        Approval(step="outline", decision="maybe")


def test_merge_reducer():
    a = Section(id="a", title="A", markdown="x")
    b = Section(id="b", title="B", markdown="y")
    assert merge({"a": a}, {"b": b}) == {"a": a, "b": b}
    assert merge(None, {"b": b}) == {"b": b}


@pytest.mark.parametrize("raw, expected", [
    ("83.2", 83.2), ("-9.2", -9.2), ("11663", 11663), (" 42 ", 42), (12.5, 12.5), (None, None),
    ("2026-03", "2026-03"), ("LummaStealer", "LummaStealer"), ("1,234", "1,234"), ("12%", "12%"),
])
def test_numbers_written_as_text_become_numbers(raw, expected):
    f = FindingDraft(**{**DRAFT, "values": {"pct_change": raw}})
    assert f.values["pct_change"] == expected and type(f.values["pct_change"]) is type(expected)
