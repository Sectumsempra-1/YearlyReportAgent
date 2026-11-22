"""Tests for verify.py (SPEC 9): numbers, tags, rounding, assignment,
recommendations and consistency across sections.

A tiny database with hand-picked counts gives known values:

  compare_years(2026, "Firewall", "intrusion_attempt") -> 225 vs 200, change 25, +12.5%
  compare_years(2026, "Firewall", "brute_force")       -> 12345 vs 10000, change 2345, +23.5%
                                                          (23.45 rounded half-up)
  compare_years(2026, "EDR", "ransomware")             -> 30 vs 40, change -10, -25.0%
  top_countries(2026, n=2)                             -> total 12600; RU 12345 (98.0%), CN 225 (1.8%)
"""

import io
from pathlib import Path

import pytest

import ingest
from agents.state import Finding, Section
from verify import (
    SourceCache, check_consistency, check_section, section_quotes, sentence_at, verify_section,
)

HEADER = ",".join(ingest.COLUMNS)
DATA = {
    "firewall_2025.csv": ["Firewall,2025-01,intrusion_attempt,blocked,,CN,Energy,high,200",
                          "Firewall,2025-01,brute_force,blocked,,RU,Finance,medium,10000"],
    "firewall_2026.csv": ["Firewall,2026-01,intrusion_attempt,blocked,,CN,Energy,high,225",
                          "Firewall,2026-01,brute_force,blocked,,RU,Finance,medium,12345"],
    "edr_2025.csv": ["EDR,2025-01,ransomware,blocked,,BR,Energy,critical,40"],
    "edr_2026.csv": ["EDR,2026-01,ransomware,blocked,,BR,Energy,critical,30"],
}


@pytest.fixture(scope="module")
def known_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("verify_db")
    for name, rows in DATA.items():
        (folder / name).write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    db = folder / "report.db"
    assert ingest.run([folder], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    return db


@pytest.fixture(autouse=True)
def db(known_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(known_db))


def finding(fid, function, params, key_paths, values, product="Firewall", data_gap=False, direction="up"):
    return Finding(id=fid, product=product, statement="s", values=values, direction=direction,
                   data_gap=data_gap, source={"function": function, "params": params, "key_paths": key_paths})


CMP = {"cur": "value.current", "prev": "value.previous", "chg": "value.change", "pct": "value.pct_change"}
F1 = finding("F-001", "compare_years", {"year": 2026, "product": "Firewall", "attack_type": "intrusion_attempt"},
             CMP, {"cur": 225, "prev": 200, "chg": 25, "pct": 12.5})
F2 = finding("F-002", "compare_years", {"year": 2026, "product": "Firewall", "attack_type": "brute_force"},
             CMP, {"cur": 12345, "prev": 10000, "chg": 2345, "pct": 23.5})
F3 = finding("F-003", "compare_years", {"year": 2026, "product": "EDR", "attack_type": "ransomware"},
             CMP, {"cur": 30, "prev": 40, "chg": -10, "pct": -25.0}, product="EDR", direction="down")
F4 = finding("F-004", "top_countries", {"year": 2026, "n": 2},
             {"share": "value.rows.0.share_pct", "vol": "value.rows.0.volume", "total": "value.total"},
             {"share": 98.0, "vol": 12345, "total": 12600}, product="ALL")
F5 = finding("F-005", "unmapped_malware", {"year": 2026}, {}, {}, product="ALL", data_gap=True)
ALL = {f.id: f for f in (F1, F2, F3, F4, F5)}


def section(markdown, sid="trends"):
    return Section(id=sid, title=sid, markdown=markdown)


def errors(markdown, assigned=("F-001", "F-002", "F-003", "F-004", "F-005"), sid="trends"):
    errs, _ = check_section(section(markdown, sid), {fid: ALL[fid] for fid in assigned})
    return errs


def problems(markdown, **kw):
    return [e.problem for e in errors(markdown, **kw)]


# --- correct numbers -------------------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    "Intrusion attempts rose 12.5% [F-001], from 200 [F-001] to 225 [F-001].",
    "Brute force rose to 12,345 [F-002] from 10,000 [F-002].",
    "Brute force rose to 12345 [F-002].",
    "Ransomware fell 25.0% [F-003], a change of -10 [F-003].",
    "Ransomware fell -25.0% [F-003].",                          # sign ignored; wording check judges it
    "Most traffic, 12,345 [F-004] events or 98.0% [F-004], came from one country.",
    "The top 2 [F-004] countries are listed.",                  # a numeric call argument
    "Blocked attacks rose (225) [F-001] this year.",            # closing bracket before the tag
    "Intrusions rose 12.5%[F-001].",                            # no space before the tag
    "Both rose: 12.5% [F-001, F-002] and 23.5% [F-001, F-002].",  # a multi-tag: any of them may match
    "",
    "No numbers here, only words [F-005].",
])
def test_correct_numbers_pass(text):
    assert errors(text) == []


# --- wrong numbers ----------------------------------------------------------------------------------------

def test_wrong_number():
    [e] = errors("Intrusion attempts rose 13.5% [F-001] this year.")
    assert e.problem == "13.5% does not match F-001"
    assert e.sentence == "Intrusion attempts rose 13.5% [F-001] this year."
    assert e.expected == "F-001: cur=225, prev=200, chg=25, pct=12.5"


def test_number_from_another_finding_does_not_match():
    assert problems("Brute force reached 12,345 [F-001].") == ["12,345 does not match F-001"]


def test_calculated_number_fails():
    # 12345 + 225 = 12570: a sum nobody returned
    assert problems("Together they reached 12,570 [F-001, F-002].") == ["12,570 does not match F-001, F-002"]


def test_stored_value_is_not_trusted_the_source_is_rerun():
    stale = F1.model_copy(update={"values": {**F1.values, "pct": 99.0}})
    findings = {"F-001": stale}
    assert check_section(section("Rose 12.5% [F-001]."), findings)[0] == []
    [e] = check_section(section("Rose 99.0% [F-001]."), findings)[0]
    assert e.problem == "99.0% does not match F-001" and "pct=12.5" in e.expected


def test_source_that_cannot_be_rerun():
    broken = finding("F-009", "compare_years", {"year": 2026, "product": "Nope"},
                     {"pct": "value.pct_change"}, {"pct": 1.0})
    [e] = check_section(section("Rose 1.0% [F-009]."), {"F-009": broken})[0]
    assert "F-009's source compare_years could not be re-run" in e.problem and "Nope" in e.problem


# --- rounding ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, ok", [
    ("rose 12.5% [F-001]", True),
    ("rose 13% [F-001]", True),       # 12.5 rounds half-up to 13
    ("rose 12% [F-001]", False),
    ("rose 12.50% [F-001]", True),    # more decimals, same value
    ("rose 12.6% [F-001]", False),
    ("rose 23.5% [F-002]", True),
    ("rose 24% [F-002]", True),       # 23.5 -> 24
    ("rose 23% [F-002]", False),
    ("rose 23.45% [F-002]", False),   # the tool returns 23.5; 23.45 is not that value
    ("fell 25% [F-003]", True),
    ("fell 25.00% [F-003]", True),
    ("fell 24.9% [F-003]", False),
    ("share 98% [F-004]", True),
    ("share 97.9% [F-004]", False),
    ("about 12,000 [F-002]", False),  # no rounding to thousands
])
def test_rounding(text, ok):
    assert (errors(text) == []) is ok, errors(text)


# --- missing tags -------------------------------------------------------------------------------------------

@pytest.mark.parametrize("text, number", [
    ("Intrusion attempts rose 12.5% this year.", "12.5%"),
    ("Intrusion attempts rose 12.5% in total [F-001].", "12.5%"),       # tag not directly after it
    ("Brute force reached 12,345 [F-002], up from 10,000.", "10,000"),
    ("High severity was 98.0% of events (12,345) [F-004].", "98.0%"),   # one tag does not cover both
    ("### Top 3 risks\n\nRose 12.5% [F-001].", "3"),                    # numbers in headings count
    ("Three products reported, about 1.2 thousand events.", "1.2"),
])
def test_untagged_numbers(text, number):
    found = errors(text)
    assert [e.problem for e in found] == [f"the number {number} has no finding tag directly after it"]
    assert found[0].expected == "a tag like [F-001] right after the number"


@pytest.mark.parametrize("text", [
    "In 2026, compared with 2025, intrusions rose 12.5% [F-001].",   # years
    "The peak was in 2026-03 and the low in 2026-10.",               # year-months
    "This maps to T1110 and T1566.001.",                             # ATT&CK IDs
    "Malware such as Win32/Kryptik.gen was not mapped [F-005].",     # digits in a name
    "1. Intrusions rose 12.5% [F-001].\n2. Brute force rose 23.5% [F-002].",  # numbered-list markers
])
def test_not_numbers(text):
    assert errors(text) == []


# --- tags must point to the section's findings -------------------------------------------------------------

def test_tag_to_unassigned_finding():
    found = errors("Brute force rose 23.5% [F-002].", assigned=("F-001",))
    assert [e.problem for e in found] == ["F-002 is not one of this section's findings"]
    assert found[0].expected == "one of F-001"


def test_unassigned_tag_without_a_number_is_flagged_once():
    found = errors("See [F-003]. Again [F-003]. And rose 12.5% [F-001].", assigned=("F-001",))
    assert [e.problem for e in found] == ["F-003 is not one of this section's findings"]


def test_multi_tag_with_an_unassigned_finding():
    found = errors("Rose 12.5% [F-001, F-002].", assigned=("F-001",))
    assert [e.problem for e in found] == ["F-002 is not one of this section's findings"]


def test_tag_to_a_finding_that_does_not_exist():
    assert problems("Rose 12.5% [F-777].", assigned=("F-001",)) == ["F-777 is not one of this section's findings"]


def test_executive_summary_scope_is_what_it_is_given():
    # the summary's verifier passes the findings used in verified sections
    assert errors("Rose 12.5% [F-001] and fell 25% [F-003].", assigned=("F-001", "F-003"),
                  sid="executive_summary") == []


# --- recommendations ------------------------------------------------------------------------------------------

def test_recommendations_each_bullet_tagged():
    text = ("Based on the findings:\n\n"
            "- Harden remote access, as brute force rose 23.5% [F-002].\n"
            "- Review ransomware playbooks [F-003],\n"
            "  even though attempts fell.\n"
            "* Map the unmapped names [F-005].")
    assert errors(text, sid="recommendations") == []


def test_recommendation_without_a_tag():
    text = "- Harden remote access [F-002].\n- Train staff on phishing.\n- Patch systems,\n  then audit [F-001]."
    found = errors(text, sid="recommendations")
    assert [(e.problem, e.sentence) for e in found] == [
        ("this recommendation cites no finding", "- Train staff on phishing.")]


def test_recommendations_must_be_bullets():
    found = errors("We recommend hardening remote access [F-002].", sid="recommendations")
    assert [e.problem for e in found] == ["the recommendations are not bullets"]


def test_bullet_rule_only_applies_to_recommendations():
    assert errors("A paragraph without bullets [F-002].", sid="trends") == []


# --- several problems in one section ---------------------------------------------------------------------------

def test_all_problems_are_reported():
    text = "Rose 13.5% [F-001]. Fell 25%. See [F-004]. Top 2 [F-004]."
    found = problems(text, assigned=("F-001", "F-003"))
    assert found == ["F-004 is not one of this section's findings",
                     "13.5% does not match F-001",
                     "the number 25% has no finding tag directly after it"]


def test_verify_section_result():
    ok = verify_section(section("Rose 12.5% [F-001]."), {"F-001": F1})
    assert ok.passed and ok.errors == []
    bad = verify_section(section("Rose 12%."), {"F-001": F1})
    assert not bad.passed and bad.section_id == "trends" and len(bad.errors) == 1


def test_sentence_at():
    text = "First sentence. Second one has 12.5% [F-001]! Third?\n- A bullet with 3"
    assert sentence_at(text, text.index("12.5")) == "Second one has 12.5% [F-001]!"
    assert sentence_at(text, text.index("3")) == "- A bullet with 3"


# --- consistency across sections --------------------------------------------------------------------------------

def quotes(**sections):
    secs = {sid: Section(id=sid, title=sid, markdown=md,
                         finding_ids_used=[fid for fid in ALL if f"[{fid}" in md or f", {fid}" in md])
            for sid, md in sections.items()}
    return section_quotes(secs, ALL, SourceCache())


def test_same_value_quoted_the_same_way_is_consistent():
    assert check_consistency(quotes(product_performance="Rose 12.5% [F-001].",
                                    trends="Intrusions rose 12.5% [F-001].")) == {}


def test_same_value_quoted_differently_flags_the_later_section():
    found = check_consistency(quotes(trends="Intrusions rose 13% [F-001].",
                                     product_performance="Rose 12.5% [F-001]."))
    assert list(found) == ["trends"]   # product_performance comes first in the report
    [e] = found["trends"]
    assert e.problem == "13% quotes F-001 (pct) differently from the product_performance section, which has 12.5%"
    assert e.expected == "12.5%" and e.sentence == "Intrusions rose 13% [F-001]."


def test_thousands_separator_is_not_a_difference():
    assert check_consistency(quotes(product_performance="Reached 12,345 [F-002].",
                                    trends="Reached 12345 [F-002].")) == {}


def test_different_values_of_one_finding_are_not_a_conflict():
    assert check_consistency(quotes(product_performance="Rose 12.5% [F-001].",
                                    trends="From 200 [F-001] to 225 [F-001].")) == {}


def test_call_arguments_are_not_checked_for_consistency():
    assert check_consistency(quotes(source_countries="The top 2 [F-004].",
                                    trends="Share 98.0% [F-004] of the top 2 [F-004].")) == {}


def test_three_sections_two_differ():
    found = check_consistency(quotes(product_performance="Rose 12.5% [F-001].",
                                     trends="Rose 13% [F-001].",
                                     recommendations="- Act, it rose 13% [F-001]."))
    assert set(found) == {"trends", "recommendations"}


def test_executive_summary_is_checked_against_verified_sections():
    q = quotes(executive_summary="Intrusions rose 13% [F-001].", product_performance="Rose 12.5% [F-001].")
    # by report order the summary would be the reference; with verified sections as reference it is flagged
    found = check_consistency(q, reference_sections={"product_performance"})
    assert list(found) == ["executive_summary"]
    assert found["executive_summary"][0].expected == "12.5%"
