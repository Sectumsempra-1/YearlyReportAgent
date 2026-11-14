"""Synthesizer (SPEC 7.3).

STUB: builds a fixed outline that spreads the findings over the sections,
instead of calling the model. On a rejected outline it re-runs with the
reviewer's comment (state["outline_feedback"]).

The code check is real: every finding ID in the outline must exist.
Each version is saved as outline_<n>.json.
"""

from agents.runs import next_version, save
from agents.state import OUTLINE_SECTIONS, SECTION_TITLES, Outline


def check_outline(outline: Outline, finding_ids: set[str]) -> None:
    unknown = sorted(outline.finding_ids() - finding_ids)
    if unknown:
        raise ValueError(f"outline cites unknown findings: {unknown}")


def synthesizer(state: dict) -> dict:
    ids = [f.id for f in state["normalized"]]
    if not ids:
        raise ValueError("no findings to build an outline from")
    thesis = "STUB thesis."
    if state.get("outline_feedback"):
        thesis += f" Revised after review: {state['outline_feedback']}"
    outline = Outline(
        thesis=thesis,
        signature_metric={"finding_id": ids[0], "value_key": next(iter(state["normalized"][0].values), "")},
        themes=[{"title": f"STUB theme {n}", "summary": "STUB summary.", "finding_ids": [ids[n % len(ids)]]}
                for n in range(3)],
        sections=[{"id": sid, "title": SECTION_TITLES[sid], "goal": "STUB goal.",
                   "finding_ids": [ids[n % len(ids)]]}
                  for n, sid in enumerate(OUTLINE_SECTIONS)],
    )
    check_outline(outline, set(ids))
    save(state["run_dir"], f"outline_{next_version(state['run_dir'], 'outline')}.json", outline)
    return {"outline": outline}
