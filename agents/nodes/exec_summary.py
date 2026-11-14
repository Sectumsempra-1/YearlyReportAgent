"""Executive summary (SPEC 7.6). No tools.

STUB: returns fixed fake Markdown instead of calling the model.

Input: LoopState with the approved outline, the verified sections, the
findings they use, and on a rejected report the reviewer's comment.
Output: {"draft": Section}. Verified like any section.
"""

from agents.state import EXEC_SUMMARY_ID, SECTION_TITLES, Section


def exec_summary(state: dict) -> dict:
    finding = state["findings"][0]
    key, value = next(iter(finding.values.items()), ("", ""))
    markdown = f"STUB executive summary. {state['outline'].thesis} {key}: {value} [{finding.id}]."
    if state.get("feedback"):
        markdown += f" Revised after review: {state['feedback']}"
    return {"draft": Section(id=EXEC_SUMMARY_ID, title=SECTION_TITLES[EXEC_SUMMARY_ID],
                             markdown=markdown, finding_ids_used=[finding.id])}
