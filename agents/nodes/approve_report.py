"""Final human approval before publishing (SPEC 7.6). Code, no model.

Pauses the graph with interrupt(). A rejection sends the executive summary
back to its writer with the comment; an abort ends the run.
"""

from langgraph.types import interrupt

from agents.runs import append
from agents.state import EXEC_SUMMARY_ID, OUTLINE_SECTIONS, Approval


def format_report(sections: dict) -> str:
    summary = sections[EXEC_SUMMARY_ID]
    lines = ["REPORT FOR APPROVAL", "", f"## {summary.title}", "", summary.markdown, "",
             "Verified sections:"]
    lines += [f"  - {sections[sid].title}" for sid in OUTLINE_SECTIONS if sid in sections]
    return "\n".join(lines)


def approve_report(state: dict) -> dict:
    answer = interrupt({"step": "report", "text": format_report(state["sections"])})
    approval = Approval(step="report", **answer)
    append(state["run_dir"], "approvals.json", approval)
    update: dict = {"approvals": [approval]}
    if approval.decision == "reject":
        update["report_feedback"] = approval.comment
    elif approval.decision == "abort":
        update["status"] = "aborted"
    return update
