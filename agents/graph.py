"""The report pipeline as a LangGraph graph (docs/SPEC.md section 7).

    load_products
      -> analyst (one per product) + cross_product_analyst      [parallel]
      -> collect_findings -> normalizer -> synthesizer
      -> approve_outline        [pause: approve / reject -> synthesizer / abort]
      -> section_loop (one per outline section)                  [parallel]
           each: write -> verify -> pass: done | fail: rewrite | 4th failure: stop
      -> sections_done          [any section failed -> report_failures -> end;
                                 a value quoted differently than in an earlier
                                 section -> that section_loop again, same attempt count]
      -> summary_loop (same write/verify/retry loop)
      -> approve_report         [pause: approve / reject -> summary_loop / abort]
      -> assemble -> end

Nodes live in agents/nodes/, one module per node. build_graph() takes
replacement nodes by name, so tests can swap in fakes (e.g. a failing verifier).
Routing decisions are plain functions so they can be tested on their own.
"""

from typing import Callable, Literal

from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
from langgraph.graph import END, START, StateGraph
from langgraph.types import Send

from agents.nodes.analyst import analyst
from agents.nodes.approve_outline import approve_outline
from agents.nodes.approve_report import approve_report
from agents.nodes.assemble import assemble
from agents.nodes.collect_findings import collect_findings
from agents.nodes.cross_product_analyst import cross_product_analyst
from agents.nodes.exec_summary import exec_summary
from agents.nodes.load_products import load_products
from agents.nodes.normalizer import normalizer
from agents.nodes.report_failures import report_failures
from agents.nodes.section_writer import section_writer
from agents.nodes.synthesizer import synthesizer
from agents.nodes.verifier import verifier
from agents.runs import save
from agents import state as state_models
from agents.nodes.check_sections import check_sections
from agents.state import (
    EXEC_SUMMARY_ID, MAX_ATTEMPTS, OUTLINE_SECTIONS, SECTION_TITLES, LoopState, ReportState,
    VerificationResult,
)


DEFAULT_NODES: dict[str, Callable] = {
    "load_products": load_products,
    "analyst": analyst,
    "cross_product_analyst": cross_product_analyst,
    "collect_findings": collect_findings,
    "normalizer": normalizer,
    "synthesizer": synthesizer,
    "approve_outline": approve_outline,
    "section_writer": section_writer,
    "verifier": verifier,
    "exec_summary": exec_summary,
    "approve_report": approve_report,
    "assemble": assemble,
    "report_failures": report_failures,
}


# --- routing (plain functions) -----------------------------------------------------------------

def decide_after_verify(passed: bool, attempt: int, max_attempts: int = MAX_ATTEMPTS
                        ) -> Literal["done", "rewrite", "stop"]:
    """A pass moves on; a fail goes back to the writer until max_attempts is used up."""
    if passed:
        return "done"
    return "rewrite" if attempt < max_attempts else "stop"


def route_after_verify(state: LoopState) -> str:
    return decide_after_verify(state["verification"].passed, state["attempt"])


def last_decision(state: ReportState, step: str) -> str:
    return next(a.decision for a in reversed(state["approvals"]) if a.step == step)


def fan_out_analysts(state: ReportState) -> list[Send]:
    base = {"year": state["year"], "run_dir": state["run_dir"]}
    return ([Send("analyst", {**base, "product": p}) for p in state["products"]]
            + [Send("cross_product_analyst", base)])


def _loop_payload(state: ReportState, section_id: str, title: str, goal: str, finding_ids) -> dict:
    wanted = set(finding_ids)
    return {"year": state["year"], "run_dir": state["run_dir"], "section_id": section_id,
            "title": title, "goal": goal, "outline": state["outline"],
            "findings": [f for f in state["normalized"] if f.id in wanted], "attempt": 0}


def route_after_outline(state: ReportState):
    decision = last_decision(state, "outline")
    if decision == "abort":
        return END
    if decision == "reject":
        return "synthesizer"
    return [Send("section_loop", _loop_payload(state, s.id, s.title, s.goal, s.finding_ids))
            for s in state["outline"].sections]


def summary_payload(state: ReportState) -> dict:
    verified = {sid: state["sections"][sid] for sid in OUTLINE_SECTIONS}
    used = {fid for s in verified.values() for fid in s.finding_ids_used}
    payload = _loop_payload(state, EXEC_SUMMARY_ID, SECTION_TITLES[EXEC_SUMMARY_ID],
                            "Thesis, headline numbers, one paragraph per theme, top recommendations.", used)
    rejections = sum(1 for a in state.get("approvals", []) if a.step == "report" and a.decision == "reject")
    return {**payload, "verified_sections": verified, "feedback": state.get("report_feedback", ""),
            "round": rejections + 1}


def route_after_sections(state: ReportState):
    """Any failed section stops the run. Sections that quote a value differently from an
    earlier section go back to their writer with the errors. Otherwise: executive summary."""
    if any(sid in state.get("failed", {}) for sid in OUTLINE_SECTIONS):
        return "report_failures"
    conflicts = state.get("conflicts") or {}
    if conflicts:
        sends = []
        for s in state["outline"].sections:
            if s.id in conflicts:
                payload = _loop_payload(state, s.id, s.title, s.goal, s.finding_ids)
                sends.append(Send("section_loop", {
                    **payload, "attempt": state["attempts"][s.id], "draft": state["sections"][s.id],
                    "verification": VerificationResult(section_id=s.id, passed=False,
                                                       errors=conflicts[s.id])}))
        return sends
    return Send("summary_loop", summary_payload(state))


def route_after_summary(state: ReportState) -> str:
    return "report_failures" if EXEC_SUMMARY_ID in state.get("failed", {}) else "approve_report"


def route_after_report(state: ReportState):
    decision = last_decision(state, "report")
    if decision == "abort":
        return END
    if decision == "reject":
        return Send("summary_loop", summary_payload(state))
    return "assemble"


# --- write -> verify -> retry loop ------------------------------------------------------------------

def build_loop(writer: Callable, check: Callable):
    """Subgraph for one section: write, verify, then route by decide_after_verify."""

    def name(state: LoopState, kind: str) -> str:
        """e.g. section_trends_attempt2.json; later rounds add _round<n> so nothing is overwritten."""
        rnd = state.get("round", 1)
        return (f"{kind}_{state['section_id']}" + (f"_round{rnd}" if rnd > 1 else "")
                + f"_attempt{state['attempt']}.json")

    def write(state: LoopState) -> dict:
        state = {**state, "attempt": state.get("attempt", 0) + 1}
        draft = writer(state)["draft"]
        save(state["run_dir"], name(state, "section"), draft)
        return {"draft": draft, "attempt": state["attempt"]}

    def verify(state: LoopState) -> dict:
        result = check(state)["verification"]
        save(state["run_dir"], name(state, "verify"), result)
        return {"verification": result}

    g = StateGraph(LoopState)
    g.add_node("write", write)
    g.add_node("verify", verify)
    g.add_edge(START, "write")
    g.add_edge("write", "verify")
    g.add_conditional_edges("verify", route_after_verify, {"done": END, "stop": END, "rewrite": "write"})
    return g.compile()


def _loop_node(loop):
    """Run a loop subgraph and report its outcome to the parent state."""

    def run(payload: dict) -> dict:
        final = loop.invoke(payload)
        sid, attempts = payload["section_id"], final["attempt"]
        if final["verification"].passed:
            return {"sections": {sid: final["draft"]}, "attempts": {sid: attempts}}
        return {"failed": {sid: final["verification"].errors}, "attempts": {sid: attempts}}

    return run


# --- checkpoints -----------------------------------------------------------------------------------

# The Pydantic models that may appear in graph state. Checkpoints may restore
# only these (LangGraph blocks unregistered types).
STATE_MODELS = sorted(
    name for name, obj in vars(state_models).items()
    if isinstance(obj, type) and issubclass(obj, state_models.Model) and obj is not state_models.Model
)


def checkpoint_serializer() -> JsonPlusSerializer:
    return JsonPlusSerializer(allowed_msgpack_modules=[("agents.state", name) for name in STATE_MODELS])


# --- graph -----------------------------------------------------------------------------------------

def build_graph(nodes: dict[str, Callable] | None = None, checkpointer=None):
    """Compile the pipeline. `nodes` replaces default nodes by name.

    A checkpointer is required to pause for approval and resume.
    """
    n = {**DEFAULT_NODES, **(nodes or {})}
    unknown = set(n) - set(DEFAULT_NODES)
    if unknown:
        raise ValueError(f"unknown node names: {sorted(unknown)}")

    g = StateGraph(ReportState)
    for name in ("load_products", "analyst", "cross_product_analyst", "collect_findings", "normalizer",
                 "synthesizer", "approve_outline", "approve_report", "assemble", "report_failures"):
        g.add_node(name, n[name])
    g.add_node("section_loop", _loop_node(build_loop(n["section_writer"], n["verifier"])))
    g.add_node("sections_done", check_sections)  # join: runs once after all section loops
    g.add_node("summary_loop", _loop_node(build_loop(n["exec_summary"], n["verifier"])))

    g.add_edge(START, "load_products")
    g.add_conditional_edges("load_products", fan_out_analysts, ["analyst", "cross_product_analyst"])
    g.add_edge("analyst", "collect_findings")
    g.add_edge("cross_product_analyst", "collect_findings")
    g.add_edge("collect_findings", "normalizer")
    g.add_edge("normalizer", "synthesizer")
    g.add_edge("synthesizer", "approve_outline")
    g.add_conditional_edges("approve_outline", route_after_outline, ["synthesizer", "section_loop", END])
    g.add_edge("section_loop", "sections_done")
    g.add_conditional_edges("sections_done", route_after_sections,
                            ["report_failures", "summary_loop", "section_loop"])
    g.add_conditional_edges("summary_loop", route_after_summary, ["report_failures", "approve_report"])
    g.add_conditional_edges("approve_report", route_after_report, ["assemble", "summary_loop", END])
    g.add_edge("assemble", END)
    g.add_edge("report_failures", END)
    return g.compile(checkpointer=checkpointer)
