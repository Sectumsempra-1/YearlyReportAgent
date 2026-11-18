"""Tests for the product analyst: the code check, structured output, the tool
loop and the prompt. A scripted fake model is used; no real model is called."""

import io
import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

import ingest
import report_tools as rt
from agents.finding_check import check_finding, same_value
from agents.nodes.analyst import make_analyst, run_tool_loop
from agents.nodes.collect_findings import collect_findings
from agents.prompt_loader import PROMPTS_DIR, load_prompt
from agents.state import AnalystOutput, FindingDraft
from agents.structured import StructuredOutputError, complete, parse
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


def finding(function, params, key_paths, values, product="EDR", **extra) -> FindingDraft:
    return FindingDraft(product=product, statement="s", values=values,
                        source={"function": function, "params": params, "key_paths": key_paths}, **extra)


def as_output(f: FindingDraft) -> dict:
    """A finding as the model would write it (no product)."""
    return f.model_dump(exclude={"product"})


# --- the code check -----------------------------------------------------------------------------------

def test_correct_finding_passes():
    pct = rt.compare_years(2026, product="EDR")["value"]["pct_change"]
    f = finding("compare_years", {"year": 2026, "product": "EDR"}, {"pct": "value.pct_change"}, {"pct": pct})
    assert check_finding(f, "EDR") == []


def test_wrong_value_fails():
    actual = rt.compare_years(2026, product="EDR")["value"]["pct_change"]
    f = finding("compare_years", {"year": 2026, "product": "EDR"}, {"pct": "value.pct_change"},
                {"pct": actual + 0.1})
    [problem] = check_finding(f, "EDR")
    assert problem.startswith("pct: finding says") and f"value.pct_change is {actual!r}" in problem


def test_rounded_value_fails():
    actual = rt.product_summary(2026, "EDR")["value"]
    at = next(iter(actual))
    blocked = actual[at]["blocked"]
    f = finding("product_summary", {"year": 2026, "product": "EDR"}, {"b": f"value.{at}.blocked"},
                {"b": round(blocked, -2) + 1})
    assert check_finding(f, "EDR")


def test_whole_float_matches_int_but_bool_does_not_match_int():
    assert same_value(12, 12.0) and same_value(12.5, 12.5)
    assert not same_value(1, True) and not same_value(True, 1)
    assert same_value(None, None) and not same_value(0, None)
    assert not same_value("12", 12)


def test_null_is_copied_as_null():
    f = finding("monthly_series", {"year": 2026, "product": "EDR"},
                {"mom": "value.months.0.mom_change"}, {"mom": None})
    assert check_finding(f, "EDR") == []


@pytest.mark.parametrize("path, expected", [
    ("value.nope", "not found"),
    ("value.rows.99.share_pct", "not found"),
    ("value.rows.x", "not found"),
    ("caveats.0", "must start with 'value'"),
    ("source.function", "must start with 'value'"),
])
def test_bad_key_paths(path, expected):
    f = finding("top_countries", {"year": 2026, "product": "EDR"}, {"x": path}, {"x": 1})
    [problem] = check_finding(f, "EDR")
    assert expected in problem


@pytest.mark.parametrize("params, scope, ok", [
    ({"year": 2026, "product": "EDR"}, "EDR", True),
    ({"year": 2026}, "EDR", False),                       # all products: not this analyst's scope
    ({"year": 2026, "product": "Firewall"}, "EDR", False),  # another product
    ({"year": 2026}, None, True),                         # cross-product analyst
    ({"year": 2026, "product": "EDR"}, None, False),
])
def test_scope(params, scope, ok):
    total = rt.attacks_blocked(**params)["value"]
    f = finding("attacks_blocked", params, {"t": "value"}, {"t": total})
    problems = check_finding(f, scope)
    assert (problems == []) is ok
    if not ok:
        assert "this analyst may only cite calls with" in problems[0]


def test_list_products_is_allowed_in_any_scope():
    name = rt.list_products()["value"][0]["product"]
    f = finding("list_products", {}, {"n": "value.0.product"}, {"n": name})
    assert check_finding(f, "EDR") == [] and check_finding(f, None) == []


def test_failing_call_fails():
    f = finding("attacks_blocked", {"year": 2026, "product": "EDR", "attack_type": "ddos"}, {"t": "value"},
                {"t": 1})
    [problem] = check_finding(f, "EDR")
    assert "failed" in problem and "ddos" in problem


def summary_finding(statement):
    cy = rt.compare_years(2026, product="EDR")["value"]
    f = finding("compare_years", {"year": 2026, "product": "EDR"},
                {"pct": "value.pct_change", "cur": "value.current"},
                {"pct": cy["pct_change"], "cur": cy["current"]})
    return f.model_copy(update={"statement": statement}), cy


def test_statement_numbers_from_values_pass():
    f, cy = summary_finding("")
    f = f.model_copy(update={"statement": f"Blocked attacks changed {cy['pct_change']}% to "
                                          f"{cy['current']:,} in 2026 compared with 2025."})
    assert check_finding(f, "EDR") == []


def test_statement_number_not_in_values_fails():
    f, cy = summary_finding("")
    f = f.model_copy(update={"statement": f"Blocked attacks changed {cy['pct_change']}%, rank 4 overall."})
    assert check_finding(f, "EDR") == ["statement: '4' is not one of the finding's values"]


def test_statement_may_use_call_arguments():
    rows = rt.top_countries(2026, n=5, product="EDR")["value"]["rows"]
    f = finding("top_countries", {"year": 2026, "n": 5, "product": "EDR"},
                {"share": "value.rows.0.share_pct"}, {"share": rows[0]["share_pct"]})
    f = f.model_copy(update={"statement": f"Among the top 5 countries, the first has {rows[0]['share_pct']}%."})
    assert check_finding(f, "EDR") == []


def test_statement_with_a_calculated_number_fails():
    f, cy = summary_finding("")
    invented = cy["current"] // 12   # a monthly average nobody returned
    f = f.model_copy(update={"statement": f"About {invented} attacks were blocked per month."})
    assert check_finding(f, "EDR") == [f"statement: '{invented}' is not one of the finding's values"]


def test_collect_findings_replaces_caveats_with_the_tools(tmp_path):
    total = rt.attacks_blocked(2026)["value"]
    f = finding("attacks_blocked", {"year": 2026}, {"t": "value"}, {"t": total}, product="ALL",
                caveats=["an invented caveat"])
    [out] = collect_findings({"drafts": [f], "run_dir": str(tmp_path)})["findings"]
    assert out.caveats == rt.attacks_blocked(2026)["caveats"]


# --- structured output ------------------------------------------------------------------------------------

GOOD = {"findings": []}


@pytest.mark.parametrize("text", [
    json.dumps(GOOD),
    "```json\n" + json.dumps(GOOD) + "\n```",
    "Here are my findings:\n" + json.dumps(GOOD) + "\nDone.",
    "<think>let me think {not json}</think>" + json.dumps(GOOD),
])
def test_parse_accepts_wrapped_json(text):
    assert parse(text, AnalystOutput) == AnalystOutput(findings=[])


@pytest.mark.parametrize("text, message", [
    ("no json here", "no JSON object"),
    ("{not: json}", "invalid JSON"),
])
def test_parse_rejects(text, message):
    with pytest.raises(ValueError, match=message):
        parse(text, AnalystOutput)


def test_complete_retries_once_with_the_error():
    llm = FakeChatModel([GOOD])
    messages = []
    out = complete(llm, messages, AnalystOutput, reply=AIMessage(content='{"findings": "oops"}'))
    assert out == AnalystOutput(findings=[])
    assert isinstance(messages[0], HumanMessage) and "could not be used" in messages[0].content
    assert "findings" in messages[0].content   # the validation error is passed back


def test_complete_fails_clearly_after_one_retry():
    llm = FakeChatModel(["still not json"])
    with pytest.raises(StructuredOutputError, match="AnalystOutput: invalid output after one retry"):
        complete(llm, [], AnalystOutput, reply=AIMessage(content="not json"))
    assert len(llm.calls) == 1   # exactly one retry


# --- the analyst node ---------------------------------------------------------------------------------------

def scripted_findings():
    cy = rt.compare_years(2026, product="EDR")
    good = finding("compare_years", {"year": 2026, "product": "EDR"},
                   {"pct_change": "value.pct_change", "current": "value.current"},
                   {"pct_change": cy["value"]["pct_change"], "current": cy["value"]["current"]},
                   caveats=cy["caveats"])
    unmapped = rt.unmapped_malware(2026, product="EDR")["value"]["rows"]
    gap = finding("unmapped_malware", {"year": 2026, "product": "EDR"},
                  {"rows": "value.rows.0.detections"} if unmapped else {},
                  {"rows": unmapped[0]["detections"]} if unmapped else {}, data_gap=True)
    wrong = finding("compare_years", {"year": 2026, "product": "EDR"}, {"p": "value.pct_change"},
                    {"p": 99.9})
    out_of_scope = finding("attacks_blocked", {"year": 2026}, {"t": "value"},
                           {"t": rt.attacks_blocked(2026)["value"]})
    bad_path = finding("product_summary", {"year": 2026, "product": "EDR"}, {"x": "value.nothing"},
                       {"x": 1})
    return [good, gap, wrong, out_of_scope, bad_path]


def test_analyst_node(tmp_path):
    findings = scripted_findings()
    llm = FakeChatModel([
        [("list_products", {}), ("compare_years", {"year": 2026, "product": "EDR"})],
        {"findings": [as_output(f) for f in findings]},
    ])
    out = make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})

    # good finding and data gap kept; product set by code
    kept = out["drafts"]
    assert [f.statement for f in kept] == ["s", "s"] and [f.data_gap for f in kept] == [False, True]
    assert all(f.product == "EDR" for f in kept)

    # the three bad findings were dropped and logged with reasons
    dropped = json.loads((tmp_path / "analyst_edr_dropped.json").read_text(encoding="utf-8"))
    assert len(dropped) == 3
    reasons = " | ".join(p for d in dropped for p in d["problems"])
    assert "finding says 99.9" in reasons
    assert "this analyst may only cite calls with product='EDR'" in reasons
    assert "not found" in reasons
    assert len(json.loads((tmp_path / "analyst_edr.json").read_text(encoding="utf-8"))) == 2

    # the model got all tools, and the real tool results
    assert len(llm.bound_tools) == len(rt.TOOLS)
    tool_messages = [m for m in llm.calls[1] if isinstance(m, ToolMessage)]
    assert json.loads(tool_messages[1].content) == rt.compare_years(2026, product="EDR")

    transcript = json.loads((tmp_path / "analyst_edr_transcript.json").read_text(encoding="utf-8"))
    assert [c["tool"] for c in transcript["tool_calls"]] == ["list_products", "compare_years"]
    assert transcript["tool_calls"][1]["result"]["source"]["function"] == "compare_years"


def test_system_prompt_is_filled_in(tmp_path):
    llm = FakeChatModel([GOOD])
    make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})
    system = llm.calls[0][0].content
    assert 'product="EDR"' in system and "year=2026" in system and "compared with 2025" in system
    assert "$" not in system


def test_unknown_tool_is_reported_to_the_model(tmp_path):
    llm = FakeChatModel([[("run_sql", {"query": "x"})], GOOD])
    make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})
    [tool_message] = [m for m in llm.calls[1] if isinstance(m, ToolMessage)]
    assert "Unknown tool 'run_sql'" in tool_message.content


def test_bad_tool_arguments_are_reported_to_the_model(tmp_path):
    llm = FakeChatModel([[("attacks_blocked", {"year": 2026, "product": "Nope"})], GOOD])
    make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})
    [tool_message] = [m for m in llm.calls[1] if isinstance(m, ToolMessage)]
    assert "unknown product 'Nope'" in tool_message.content


def test_repeated_call_points_back_instead_of_repeating():
    llm = FakeChatModel([[("list_products", {})], [("list_products", {}), ("top_countries", {"year": 2026})],
                         GOOD])
    messages, transcript = [HumanMessage("go")], []
    run_tool_loop(llm, messages, transcript)
    tool_messages = [m for m in messages if isinstance(m, ToolMessage)]
    assert json.loads(tool_messages[0].content) == rt.list_products()
    assert "already made this exact call" in tool_messages[1].content
    assert json.loads(tool_messages[2].content)["source"]["function"] == "top_countries"
    assert [c["result"] == "(repeat)" for c in transcript] == [False, True, False]


def test_tool_results_are_sent_as_compact_json():
    llm = FakeChatModel([[("list_products", {})], GOOD])
    messages = [HumanMessage("go")]
    run_tool_loop(llm, messages, [])
    content = next(m for m in messages if isinstance(m, ToolMessage)).content
    assert ", " not in content.split('"description"')[0] and ": " not in content.split('"description"')[0]


def test_tool_budget_forces_a_final_answer():
    llm = FakeChatModel([[("list_products", {})], [("list_products", {})], GOOD])
    messages, transcript = [HumanMessage("go")], []
    reply = run_tool_loop(llm, messages, transcript, max_rounds=2)
    assert parse(reply.content, AnalystOutput) == AnalystOutput(findings=[])
    assert "used all your tool calls" in llm.calls[-1][-1].content
    assert len(transcript) == 2


def test_invalid_output_fails_but_keeps_the_transcript(tmp_path):
    llm = FakeChatModel([[("list_products", {})], "not json", "still not json"])
    with pytest.raises(StructuredOutputError):
        make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})
    transcript = json.loads((tmp_path / "analyst_edr_transcript.json").read_text(encoding="utf-8"))
    assert transcript["replies"] == ["not json", "still not json"]


def test_model_cannot_set_code_only_fields(tmp_path):
    f = as_output(scripted_findings()[0])
    llm = FakeChatModel([{"findings": [{**f, "id": "F-001"}]}, {"findings": [{**f, "id": "F-001"}]}])
    with pytest.raises(StructuredOutputError, match="id"):
        make_analyst(llm)({"year": 2026, "product": "EDR", "run_dir": str(tmp_path)})


# --- the prompt -----------------------------------------------------------------------------------------------

PROMPT = (PROMPTS_DIR / "analyst.md").read_text(encoding="utf-8")


def test_prompt_has_the_required_instructions():
    text = PROMPT.lower()
    for phrase in ["explore before you conclude", "never calculate", "exactly as the tool returned",
                   "key_paths", "params", "function", "copy the caveats", "word for word",
                   '"data_gap": true', "never fill in a missing value"]:
        assert phrase in text, phrase


def test_prompt_placeholders_are_all_filled():
    text = load_prompt("analyst", product="P", year=2030, previous_year=2029)
    assert "$" not in text
    with pytest.raises(KeyError):
        load_prompt("analyst", product="P")
