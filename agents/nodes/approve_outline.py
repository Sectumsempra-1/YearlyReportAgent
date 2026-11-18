"""Human approval of the outline (SPEC 7.3). Code, no model.

Pauses the graph with interrupt() and shows the outline readably: the thesis,
the signature metric, the themes, and each section with its findings'
statements, then the findings no section uses and the data gaps. The run
resumes with {"decision": "approve" | "reject" | "abort", "comment": "..."}.
A rejection sends the outline back to the synthesizer with the comment.
"""

import textwrap

from langgraph.types import interrupt

from agents.runs import append
from agents.state import Approval, Outline

WIDTH = 100


def _wrap(text: str, indent: str) -> list[str]:
    return textwrap.wrap(text, WIDTH, initial_indent=indent, subsequent_indent=indent) or [indent]


def _finding_line(fid: str, by_id: dict, indent: str) -> list[str]:
    f = by_id.get(fid)
    if f is None:
        return [f"{indent}{fid}  (unknown finding)"]
    mark = " [data gap]" if f.data_gap else ""
    # continuation lines line up under the statement, after "F-001  "
    hanging = " " * (len(indent) + len(fid) + 2)
    return textwrap.wrap(f"{fid}  {f.statement}{mark}", WIDTH, initial_indent=indent,
                         subsequent_indent=hanging)


def format_outline(outline: Outline, findings: list) -> str:
    by_id = {f.id: f for f in findings}
    rule = "=" * WIDTH
    lines = [rule, "OUTLINE FOR APPROVAL", rule, ""]
    lines += _wrap(f"Thesis: {outline.thesis}", "")

    metric = outline.signature_metric
    f = by_id.get(metric.finding_id)
    value = f.values.get(metric.value_key) if f else None
    lines += [""] + _wrap(f"Signature metric: {metric.value_key} = {value}  ({metric.finding_id}"
                          + (f": {f.statement})" if f else ")"), "")

    lines += ["", "THEMES (most important first)", ""]
    for n, theme in enumerate(outline.themes, 1):
        lines += _wrap(f"{n}. {theme.title}", "  ")
        lines += _wrap(theme.summary, "     ")
        lines += _wrap(f"Findings: {', '.join(theme.finding_ids)}", "     ")
        lines.append("")

    lines += ["SECTIONS", ""]
    for section in outline.sections:
        lines.append(f"  {section.title}")
        lines += _wrap(f"Goal: {section.goal}", "     ")
        for fid in section.finding_ids:
            lines += _finding_line(fid, by_id, "     - ")
        lines.append("")

    used = {fid for s in outline.sections for fid in s.finding_ids}
    unused = [f.id for f in findings if f.id not in used]
    lines.append("NOT USED IN ANY SECTION (will not appear in the report)")
    lines += [line for fid in unused for line in _finding_line(fid, by_id, "     - ")] or ["     (none)"]
    lines += ["", "DATA GAPS (also listed under Methodology and data gaps)"]
    gaps = [f.id for f in findings if f.data_gap]
    lines += [line for fid in gaps for line in _finding_line(fid, by_id, "     - ")] or ["     (none)"]
    lines += ["", rule]
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
