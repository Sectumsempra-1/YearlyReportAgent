"""Section writer (SPEC 7.4): one per outline section, in parallel. No tools.

STUB: returns fixed fake Markdown that quotes the first assigned finding,
instead of calling the model.

Input: the section's LoopState (section_id, title, goal, its findings only,
attempt, and on a rewrite the previous verification with its errors).
Output: {"draft": Section}. The graph saves each attempt.
"""

from agents.state import Section


def section_writer(state: dict) -> dict:
    finding = state["findings"][0]
    key, value = next(iter(finding.values.items()), ("", ""))
    markdown = f"STUB {state['title']} (attempt {state['attempt']}). {key}: {value} [{finding.id}]."
    return {"draft": Section(id=state["section_id"], title=state["title"], markdown=markdown,
                             finding_ids_used=[finding.id])}
