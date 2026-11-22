"""Tests for the verifier node (code checks + wording check) and how its error
list reaches the writer in the retry loop. Fake models only."""

import json

import pytest

from agents.graph import build_loop
from agents.nodes.section_writer import make_section_writer
from agents.nodes.verifier import make_verifier
from agents.state import NormalizedFinding, Section
from tests.fakes import FakeChatModel
from tests.test_verify import F1, F2, F3, db, known_db  # noqa: F401  (fixtures and known findings)

def normalized(*findings):
    """Writers get normalized findings in the pipeline."""
    return [NormalizedFinding(**f.model_dump(), confidence=0.9) for f in findings]


@pytest.fixture(autouse=True)
def in_tmp(tmp_path, monkeypatch):
    """Tests whose run folder is "." write any output files into a temporary folder."""
    monkeypatch.chdir(tmp_path)


GOOD = "Intrusion attempts rose 12.5% [F-001], from 200 [F-001] to 225 [F-001]."


def loop_state(markdown, findings=(F1,), sid="trends", **extra):
    draft = Section(id=sid, title=sid, markdown=markdown,
                    finding_ids_used=[f.id for f in findings if f.id in markdown])
    return {"year": 2026, "run_dir": extra.pop("run_dir", "."), "section_id": sid, "title": sid,
            "goal": "g", "findings": list(findings), "attempt": 1, "draft": draft, **extra}


# --- code checks first, then wording -----------------------------------------------------------------------

def test_code_errors_skip_the_wording_check():
    llm = FakeChatModel([])
    result = make_verifier(llm, wording_runs=1)(loop_state("Rose 13.5% [F-001]."))["verification"]
    assert not result.passed and result.errors[0].problem == "13.5% does not match F-001"
    assert llm.calls == []


def test_wording_check_runs_when_code_checks_pass():
    llm = FakeChatModel([{"issues": []}])
    result = make_verifier(llm, wording_runs=1)(loop_state(GOOD))["verification"]
    assert result.passed and result.errors == []
    system, human = llm.calls[0]
    assert "Section text:\n" + GOOD in human.content
    cited = json.loads(human.content.split("Findings it cites:\n", 1)[1])
    assert cited[0]["id"] == "F-001" and cited[0]["direction"] == "up"
    assert cited[0]["measures"].startswith("Attacks blocked this year compared with last year")


def test_wording_issue_fails_the_section():
    llm = FakeChatModel([{"issues": [{"sentence": "Intrusion attempts rose 12.5% [F-001], from 200 [F-001] "
                                                  "to 225 [F-001].", "words": "rose",
                                      "problem": "'rose' is fine but 'doubled' is not", "expected": "rose"}]}])
    result = make_verifier(llm, wording_runs=1)(loop_state(GOOD))["verification"]
    assert not result.passed
    assert result.errors[0].problem == "wording: 'rose': 'rose' is fine but 'doubled' is not"
    assert result.errors[0].expected == "rose"


def test_invented_quotes_are_dropped_and_saved(tmp_path):
    llm = FakeChatModel([{"issues": [{"sentence": "Attacks doubled overall.", "problem": "not doubled"}]}])
    result = make_verifier(llm, wording_runs=1)(loop_state(GOOD, run_dir=str(tmp_path)))["verification"]
    assert result.passed
    saved = json.loads((tmp_path / "wording_dropped_trends_attempt1.json").read_text())
    assert saved[0]["sentence"] == "Attacks doubled overall."


def test_wording_quote_matching_ignores_spacing_and_bold():
    text = "Intrusion attempts **rose** 12.5% [F-001]\nthis year."
    llm = FakeChatModel([{"issues": [{"sentence": "Intrusion attempts rose 12.5% [F-001] this year.",
                                      "words": "rose", "problem": "p"}]}])
    assert not make_verifier(llm, wording_runs=1)(loop_state(text))["verification"].passed


def test_wording_check_asks_for_no_reasoning(monkeypatch):
    import agents.llm
    asked = {}
    fake = FakeChatModel([{"issues": []}])

    def get_llm(reasoning_effort=None):
        asked["effort"] = reasoning_effort
        return fake

    monkeypatch.setattr(agents.llm, "get_llm", get_llm)
    make_verifier(wording_runs=1)(loop_state(GOOD))
    assert asked["effort"] == "none"


def test_wording_can_be_switched_off():
    assert make_verifier(FakeChatModel([]), wording=False)(loop_state(GOOD))["verification"].passed


def test_executive_summary_must_quote_like_the_verified_sections():
    verified = {"product_performance": Section(id="product_performance", title="p",
                                               markdown="Rose 12.5% [F-001].", finding_ids_used=["F-001"])}
    state = loop_state("Intrusions rose 13% [F-001].", sid="executive_summary", verified_sections=verified)
    result = make_verifier(FakeChatModel([]), wording=False)(state)["verification"]
    assert [e.expected for e in result.errors] == ["12.5%"]
    state = loop_state("Intrusions rose 12.5% [F-001].", sid="executive_summary", verified_sections=verified)
    assert make_verifier(FakeChatModel([]), wording=False)(state)["verification"].passed


# --- the error list goes back to the writer -----------------------------------------------------------------

def test_errors_reach_the_writer_and_the_rewrite_passes(tmp_path):
    writer_llm = FakeChatModel([
        {"markdown": "Intrusion attempts rose 13.5% [F-001], and brute force rose 23.5%."},
        {"markdown": "Intrusion attempts rose 12.5% [F-001], and brute force rose 23.5% [F-002]."},
    ])
    loop = build_loop(make_section_writer(writer_llm), make_verifier(FakeChatModel([{"issues": []}]), wording_runs=1))
    final = loop.invoke({"year": 2026, "run_dir": str(tmp_path), "section_id": "trends", "title": "Trends",
                         "goal": "g", "findings": normalized(F1, F2), "attempt": 0})
    assert final["attempt"] == 2 and final["verification"].passed

    rewrite_request = writer_llm.calls[1][1].content
    assert "Your previous draft failed verification:" in rewrite_request
    assert "- 13.5% does not match F-001" in rewrite_request
    assert "expected: F-001: cur=225, prev=200, chg=25, pct=12.5" in rewrite_request
    assert "- the number 23.5% has no finding tag directly after it" in rewrite_request

    first = json.loads((tmp_path / "verify_trends_attempt1.json").read_text())
    assert not first["passed"] and len(first["errors"]) == 2
    assert json.loads((tmp_path / "verify_trends_attempt2.json").read_text())["passed"]


def test_wording_errors_also_reach_the_writer(tmp_path):
    writer_llm = FakeChatModel([{"markdown": "Ransomware rose 25.0% [F-003]."},
                                {"markdown": "Ransomware fell 25.0% [F-003]."}])
    wording_llm = FakeChatModel([
        {"issues": [{"sentence": "Ransomware rose 25.0% [F-003].", "words": "rose",
                     "problem": "'rose' but the change is negative",
                     "expected": "fell"}]},
        {"issues": []},
    ])
    loop = build_loop(make_section_writer(writer_llm), make_verifier(wording_llm, wording_runs=1))
    final = loop.invoke({"year": 2026, "run_dir": str(tmp_path), "section_id": "trends", "title": "Trends",
                         "goal": "g", "findings": normalized(F3), "attempt": 0})
    assert final["verification"].passed and final["draft"].markdown == "Ransomware fell 25.0% [F-003]."
    assert "- wording: 'rose': 'rose' but the change is negative" in writer_llm.calls[1][1].content


def test_long_wording_problems_are_shortened():
    from agents.wording import MAX_PROBLEM_CHARS
    llm = FakeChatModel([{"issues": [{"sentence": GOOD, "words": "rose", "problem": "word " * 200,
                                      "expected": "x"}]}])
    [e] = make_verifier(llm, wording_runs=1)(loop_state(GOOD))["verification"].errors
    assert len(e.problem) <= len("wording: 'rose': ") + MAX_PROBLEM_CHARS and e.problem.endswith("…")


def test_wording_check_uses_json_mode():
    llm = FakeChatModel([{"issues": []}])
    make_verifier(llm, wording_runs=1)(loop_state(GOOD))
    assert llm.bound_kwargs == {"response_format": {"type": "json_object"}}


@pytest.mark.parametrize("issue, reason", [
    ({"words": "rose", "contradiction": False, "problem": "no contradiction"},
     "the model marked it as not a contradiction"),
    ({"words": "rose", "problem": ""}, "no problem stated"),
    ({"words": "", "problem": "p"}, "its contradicting words are not in the sentence"),
    ({"words": "doubled", "problem": "p"}, "its contradicting words are not in the sentence"),
])
def test_wording_noise_is_dropped_with_the_reason(tmp_path, issue, reason):
    llm = FakeChatModel([{"issues": [{"sentence": GOOD, **issue}]}])
    result = make_verifier(llm, wording_runs=1)(loop_state(GOOD, run_dir=str(tmp_path)))["verification"]
    assert result.passed
    [saved] = json.loads((tmp_path / "wording_dropped_trends_attempt1.json").read_text())
    assert saved["dropped_because"] == reason


def test_wording_check_does_not_see_finding_statements():
    llm = FakeChatModel([{"issues": []}])
    make_verifier(llm, wording_runs=1)(loop_state(GOOD))
    cited = json.loads(llm.calls[0][1].content.split("Findings it cites:\n", 1)[1])
    assert set(cited[0]) == {"id", "values", "direction", "measures"}


def test_wording_issue_must_be_reported_by_every_run(tmp_path):
    real = {"sentence": GOOD, "words": "rose", "problem": "real"}
    noise = {"sentence": GOOD, "words": "from 200", "problem": "noise"}
    llm = FakeChatModel([{"issues": [real, noise]}, {"issues": [{**real, "problem": "real, said again"}]}])
    result = make_verifier(llm, wording_runs=2)(loop_state(GOOD, run_dir=str(tmp_path)))["verification"]
    assert len(llm.calls) == 2
    assert [e.problem for e in result.errors] == ["wording: 'rose': real"]
    [saved] = json.loads((tmp_path / "wording_dropped_trends_attempt1.json").read_text())
    assert saved["words"] == "from 200" and saved["dropped_because"].startswith("reported in run 1 only")


def test_default_wording_runs():
    from agents.wording import RUNS
    assert RUNS == 2


class FlakyModel(FakeChatModel):
    """Raises a server error for the scripted calls marked 'error'."""

    def invoke(self, messages):
        if self.replies and self.replies[0] == "error":
            self.replies.pop(0)
            self.calls.append(list(messages))
            raise RuntimeError("Error code: 500 - prediction aborted, token repeat limit reached")
        return super().invoke(messages)


def test_server_error_is_retried():
    real = {"sentence": GOOD, "words": "rose", "problem": "real"}
    llm = FlakyModel(["error", {"issues": [real]}, {"issues": [real]}])
    result = make_verifier(llm, wording_runs=2)(loop_state(GOOD))["verification"]
    assert len(llm.calls) == 3 and [e.problem for e in result.errors] == ["wording: 'rose': real"]


def test_run_that_fails_twice_is_skipped_and_the_other_decides():
    real = {"sentence": GOOD, "words": "rose", "problem": "real"}
    llm = FlakyModel(["error", "error", {"issues": [real]}])
    result = make_verifier(llm, wording_runs=2)(loop_state(GOOD))["verification"]
    assert [e.problem for e in result.errors] == ["wording: 'rose': real"]


def test_all_runs_failing_is_an_error():
    llm = FlakyModel(["error"] * 4)
    with pytest.raises(RuntimeError, match="every run failed"):
        make_verifier(llm, wording_runs=2)(loop_state(GOOD))
