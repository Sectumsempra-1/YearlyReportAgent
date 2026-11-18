"""Tests for the graph routing and the stub pipeline. No model is called."""

import io
import json
from pathlib import Path

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

import ingest
import report_tools
import run_report
from agents import graph as graph_module
from agents.graph import MAX_ATTEMPTS, build_graph, build_loop, checkpoint_serializer, decide_after_verify
from agents.state import OUTLINE_SECTIONS, VerificationError, VerificationResult
from tests.fakes import stub_analyst, stub_normalizer, stub_section_writer, stub_synthesizer

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
    monkeypatch.setenv("LANGGRAPH_STRICT_MSGPACK", "true")  # checkpoints must restore our models
    # graph tests never call a model: the real analyst is replaced by a stub
    monkeypatch.setitem(graph_module.DEFAULT_NODES, "analyst", stub_analyst)
    monkeypatch.setitem(graph_module.DEFAULT_NODES, "normalizer", stub_normalizer)
    monkeypatch.setitem(graph_module.DEFAULT_NODES, "synthesizer", stub_synthesizer)
    monkeypatch.setitem(graph_module.DEFAULT_NODES, "section_writer", stub_section_writer)


def failing_verifier(fail_until: dict[str, int]):
    """Fails a section while its attempt number is <= fail_until[section_id]."""
    def verifier(state):
        sid = state["section_id"]
        if state["attempt"] <= fail_until.get(sid, 0):
            return {"verification": VerificationResult(section_id=sid, passed=False, errors=[
                VerificationError(sentence="x", problem=f"wrong number on attempt {state['attempt']}",
                                  expected="1")])}
        return {"verification": VerificationResult(section_id=sid, passed=True)}
    return verifier


def run_pipeline(tmp_path, answers, **nodes):
    """Run the graph to the end with the given approval answers. Returns (state, run_dir)."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    graph = build_graph(nodes=nodes, checkpointer=InMemorySaver(serde=checkpoint_serializer()))
    config = {"configurable": {"thread_id": "t"}}
    state = graph.invoke({"year": 2026, "run_id": "t", "run_dir": str(run_dir), "status": "running"}, config)
    answers = list(answers)
    while state.get("__interrupt__"):
        decision, _, comment = answers.pop(0).partition(":")
        state = graph.invoke(Command(resume={"decision": decision, "comment": comment}), config)
    assert not answers, f"unused answers: {answers}"
    return state, run_dir


def files(run_dir: Path, pattern: str) -> list[str]:
    return sorted(p.name for p in run_dir.glob(pattern))


# --- routing after verification ---------------------------------------------------------------------

def test_max_attempts_is_four():
    assert MAX_ATTEMPTS == 4


@pytest.mark.parametrize("passed, attempt, expected", [
    (True, 1, "done"),       # a pass moves on
    (True, 4, "done"),
    (False, 1, "rewrite"),   # a fail goes back to the writer
    (False, 2, "rewrite"),
    (False, 3, "rewrite"),
    (False, 4, "stop"),      # the fourth failure stops
])
def test_decide_after_verify(passed, attempt, expected):
    assert decide_after_verify(passed, attempt) == expected


def loop_payload(tmp_path):
    from agents.state import Finding
    finding = Finding(id="F-001", product="EDR", statement="s", values={"blocked": 1},
                      source={"function": "attacks_blocked", "params": {"year": 2026},
                              "key_paths": {"blocked": "value"}}, direction="up")
    return {"year": 2026, "run_dir": str(tmp_path), "section_id": "trends", "title": "Trends",
            "goal": "g", "findings": [finding], "attempt": 0}


@pytest.mark.parametrize("failures, attempts, passed", [
    (0, 1, True),    # pass on the first write
    (1, 2, True),    # one fail, back to the writer, then pass
    (3, 4, True),    # passes on the last allowed attempt
    (4, 4, False),   # fourth failure: stop, no fifth attempt
    (9, 4, False),
])
def test_loop(tmp_path, failures, attempts, passed):
    calls = []

    def writer(state):
        calls.append(state)
        return stub_section_writer(state)

    final = build_loop(writer, failing_verifier({"trends": failures})).invoke(loop_payload(tmp_path))
    assert final["attempt"] == attempts
    assert final["verification"].passed is passed
    assert len(calls) == attempts
    assert files(tmp_path, "section_trends_attempt*.json") == [
        f"section_trends_attempt{n}.json" for n in range(1, attempts + 1)]
    assert len(files(tmp_path, "verify_trends_attempt*.json")) == attempts


def test_rewrite_receives_the_errors(tmp_path):
    seen = []

    def writer(state):
        seen.append(state.get("verification"))
        return stub_section_writer(state)

    build_loop(writer, failing_verifier({"trends": 1})).invoke(loop_payload(tmp_path))
    assert seen[0] is None
    assert seen[1].errors[0].problem == "wrong number on attempt 1"


# --- full pipeline with stubs ----------------------------------------------------------------------------

def test_full_run(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve", "approve"])
    assert state["status"] == "completed"
    products = report_tools.list_products()["value"]
    assert len(files(run_dir, "analyst_*.json")) == len(products) + 1   # + cross-product analyst
    for name in ["products.json", "findings.json", "normalized.json", "review.json", "outline_1.json",
                 "approvals.json", "section_methodology.json", "report.md", "report_clean.md"]:
        assert (run_dir / name).exists(), name
    for sid in (*OUTLINE_SECTIONS, "executive_summary"):
        assert (run_dir / f"section_{sid}_attempt1.json").exists()
        assert (run_dir / f"verify_{sid}_attempt1.json").exists()

    report = (run_dir / "report.md").read_text(encoding="utf-8")
    titles = ["Executive summary", "Product performance", "Top malware", "Source countries", "Trends",
              "Recommendations", "Methodology and data gaps"]
    positions = [report.index(f"## {t}") for t in titles]
    assert positions == sorted(positions)
    assert "[F-001]" in report
    assert "[F-" not in (run_dir / "report_clean.md").read_text(encoding="utf-8")


def test_one_analyst_per_product_from_list_products(tmp_path, monkeypatch):
    real = report_tools.list_products

    def only_edr():
        result = real()
        return {**result, "value": [p for p in result["value"] if p["product"] == "EDR"]}

    monkeypatch.setattr(report_tools, "list_products", only_edr)
    state, run_dir = run_pipeline(tmp_path, ["approve", "approve"])
    assert files(run_dir, "analyst_*.json") == ["analyst_cross_product.json", "analyst_edr.json"]
    assert state["products"] == ["EDR"]


def test_findings_get_ids_and_review_list(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve", "approve"])
    ids = [f.id for f in state["findings"]]
    assert ids == [f"F-{n:03d}" for n in range(1, len(ids) + 1)]
    review = json.loads((run_dir / "review.json").read_text())
    assert review and all(r["confidence"] < 0.6 for r in review)


def test_outline_rejection_goes_back_to_synthesizer(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["reject:lead with the biggest change", "approve", "approve"])
    assert state["status"] == "completed"
    assert files(run_dir, "outline_*.json") == ["outline_1.json", "outline_2.json"]
    assert "lead with the biggest change" in state["outline"].thesis
    approvals = json.loads((run_dir / "approvals.json").read_text())
    assert [(a["step"], a["decision"]) for a in approvals] == [
        ("outline", "reject"), ("outline", "approve"), ("report", "approve")]


def test_outline_abort_ends_the_run(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["abort"])
    assert state["status"] == "aborted"
    assert files(run_dir, "section_*.json") == []
    assert not (run_dir / "report.md").exists()


def test_report_rejection_rewrites_the_summary(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve", "reject:shorter", "approve"])
    assert state["status"] == "completed"
    assert files(run_dir, "section_executive_summary*.json") == [
        "section_executive_summary_attempt1.json", "section_executive_summary_round2_attempt1.json"]
    assert "shorter" in state["sections"]["executive_summary"].markdown
    # the sections were not rewritten
    assert files(run_dir, "section_trends*.json") == ["section_trends_attempt1.json"]


def test_report_abort_writes_no_report(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve", "abort"])
    assert state["status"] == "aborted"
    assert not (run_dir / "report.md").exists()


def test_section_passing_on_fourth_attempt_moves_on(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve", "approve"],
                                  verifier=failing_verifier({"trends": 3}))
    assert state["status"] == "completed"
    assert state["attempts"]["trends"] == 4
    assert state["attempts"]["top_malware"] == 1
    assert len(files(run_dir, "section_trends_attempt*.json")) == 4


def test_fourth_failure_stops_the_run(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve"],
                                  verifier=failing_verifier({"trends": 99, "top_malware": 99}))
    assert state["status"] == "failed"
    failures = json.loads((run_dir / "failures.json").read_text())
    assert set(failures) == {"trends", "top_malware"}
    assert failures["trends"]["attempts"] == 4
    assert failures["trends"]["errors"][0]["problem"] == "wrong number on attempt 4"
    assert len(files(run_dir, "section_trends_attempt*.json")) == 4
    # the other sections still passed, but no summary or report was written
    assert set(state["sections"]) == set(OUTLINE_SECTIONS) - {"trends", "top_malware"}
    assert files(run_dir, "section_executive_summary*.json") == []
    assert not (run_dir / "report.md").exists()


def test_failing_summary_stops_the_run(tmp_path):
    state, run_dir = run_pipeline(tmp_path, ["approve"],
                                  verifier=failing_verifier({"executive_summary": 99}))
    assert state["status"] == "failed"
    assert set(json.loads((run_dir / "failures.json").read_text())) == {"executive_summary"}
    assert not (run_dir / "report.md").exists()


def test_unknown_node_name():
    with pytest.raises(ValueError, match="unknown node names"):
        build_graph(nodes={"analist": lambda s: {}})


# --- run_report.py ----------------------------------------------------------------------------------------

def scripted(*answers):
    it = iter(answers)

    def input_fn(prompt=""):
        try:
            return next(it)
        except StopIteration:
            raise EOFError
    return input_fn


@pytest.mark.parametrize("answers, code, status", [
    (["a", "a"], 0, "completed"),
    (["r", "more detail", "a", "a"], 0, "completed"),
    (["b"], 3, "aborted"),
    ([], 3, "aborted"),               # end of input counts as abort
])
def test_run_report_cli(tmp_path, answers, code, status):
    out = io.StringIO()
    assert run_report.main(["--year", "2026"], input_fn=scripted(*answers), out=out, runs_root=tmp_path) == code
    assert f"Status: {status}" in out.getvalue()
    run_dir = next(tmp_path.iterdir())
    assert (run_dir / "checkpoints.db").exists()
    assert (run_dir / "report.md").exists() == (status == "completed")


def test_ask_approval_validates_answers():
    out = io.StringIO()
    assert run_report.ask_approval(scripted("x", "r", "", "r", "why", ), out) == {
        "decision": "reject", "comment": "why"}
    assert "Please answer a, r or b." in out.getvalue()
    assert "A rejection needs a comment." in out.getvalue()


def test_writers_run_in_parallel_with_only_their_findings(tmp_path):
    import threading
    barrier = threading.Barrier(len(OUTLINE_SECTIONS), timeout=10)   # breaks unless all 5 run at once
    seen = {}

    def writer(state):
        if state["attempt"] == 1 and state["section_id"] != "executive_summary":
            barrier.wait()
            seen[state["section_id"]] = [f.id for f in state["findings"]]
        return stub_section_writer(state)

    state, _ = run_pipeline(tmp_path, ["approve", "approve"], section_writer=writer)
    assert state["status"] == "completed"
    assert set(seen) == set(OUTLINE_SECTIONS)
    for section in state["outline"].sections:
        assert seen[section.id] == section.finding_ids
