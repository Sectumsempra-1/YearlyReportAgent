"""Cross-section consistency (SPEC 9): runs once all section loops are done. Code, no model.

The same value of the same finding (same key path) must be quoted the same
way in every section. The earliest section in report order is the reference;
a later section that quotes it differently gets the errors and goes back to
its writer (the graph routes it). A rewrite counts as one of the section's
attempts: a section that has used all of them fails instead.

Output: {"conflicts": {section id: errors}} for sections to rewrite, and
{"failed": ...} for sections that have no attempts left. Each check is saved
as consistency_<n>.json.
"""

from agents.runs import next_version, save
from agents.state import MAX_ATTEMPTS, OUTLINE_SECTIONS
from verify import check_consistency, section_quotes


def check_sections(state: dict) -> dict:
    failed = state.get("failed", {})
    if any(sid in failed for sid in OUTLINE_SECTIONS):
        return {"conflicts": {}}   # the run stops anyway

    sections = {sid: state["sections"][sid] for sid in OUTLINE_SECTIONS if sid in state.get("sections", {})}
    findings = {f.id: f for f in state.get("normalized", [])}
    problems = check_consistency(section_quotes(sections, findings))

    attempts = state.get("attempts", {})
    rewrite = {sid: errs for sid, errs in problems.items() if attempts.get(sid, 0) < MAX_ATTEMPTS}
    exhausted = {sid: errs for sid, errs in problems.items() if sid not in rewrite}
    save(state["run_dir"], f"consistency_{next_version(state['run_dir'], 'consistency')}.json",
         {"rewrite": rewrite, "failed": exhausted})
    update: dict = {"conflicts": rewrite}
    if exhausted:
        update["failed"] = exhausted
    return update
