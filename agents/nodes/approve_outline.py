"""Human approval of the outline (SPEC 7.3). Code, no model.

Pauses the graph with interrupt(). The run resumes with
{"decision": "approve" | "reject" | "abort", "comment": "..."}.
A rejection sends the outline back to the synthesizer with the comment.
"""

from langgraph.types import interrupt

from agents.runs import append
from agents.state import Approval, Outline


def format_outline(outline: Outline, findings: list) -> str:
    by_id = {f.id: f for f in findings}
    lines = ["OUTLINE", "", f"Thesis: {outline.thesis}",
             f"Signature metric: {outline.signature_metric.finding_id} "
             f"({outline.signature_metric.value_key})", "", "Themes (ranked):"]
    for n, theme in enumerate(outline.themes, 1):
        lines.append(f"  {n}. {theme.title}: {theme.summary} [{', '.join(theme.finding_ids)}]")
    lines += ["", "Sections:"]
    for s in outline.sections:
        lines.append(f"  {s.title}: {s.goal}")
        for fid in s.finding_ids:
            statement = by_id[fid].statement if fid in by_id else "(unknown finding)"
            lines.append(f"      {fid}: {statement}")
    return "\n".join(lines)


def approve_outline(state: dict) -> dict:
    answer = interrupt({"step": "outline",
                        "text": format_outline(state["outline"], state.get("normalized", []))})
    approval = Approval(step="outline", **answer)
    append(state["run_dir"], "approvals.json", approval)
    update: dict = {"approvals": [approval]}
    if approval.decision == "reject":
        update["outline_feedback"] = approval.comment
    elif approval.decision == "abort":
        update["status"] = "aborted"
    return update
