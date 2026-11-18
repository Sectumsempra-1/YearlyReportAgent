"""Synthesizer (SPEC 7.3). No tools.

The model groups the normalized findings into 3-5 ranked themes, writes a
one-sentence thesis, picks the signature metric and assigns findings to the
five outline sections. Code then checks the outline (a failed check gets one
retry with the problems listed, like invalid JSON):

- every finding ID exists (SPEC 7.3)
- every section except methodology has at least one finding (SPEC 7.3; the
  schema also requires each of the five sections exactly once)
- the signature metric is a numeric value of an existing finding
- the thesis is one sentence
- the thesis, themes and section goals contain no numbers: numbers reach the
  report only through tagged findings (rule 4)

Code also tidies the outline: duplicate IDs removed, standard section titles,
sections in report order.

On a rejected outline, the model gets its previous outline and the
reviewer's comment. Each version is saved as outline_<n>.json.
"""

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage

from agents.prompt_loader import load_prompt
from agents.runs import next_version, save
from agents.state import OUTLINE_SECTIONS, SECTION_TITLES, Outline
from agents.structured import complete
from text_numbers import find_numbers

SENTENCE_BREAK = re.compile(r"[.!?]\s+(?=[A-Z])")


def _numeric(value) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def check_outline(outline: Outline, findings: list) -> list[str]:
    """The code checks from SPEC 7.3 and the rules above. Returns the problems."""
    by_id = {f.id: f for f in findings}
    problems = []

    unknown = sorted(outline.finding_ids() - set(by_id))
    if unknown:
        problems.append(f"these finding IDs do not exist: {', '.join(unknown)}")

    for section in outline.sections:
        if not section.finding_ids:
            problems.append(f"section {section.id} has no findings")

    metric = outline.signature_metric
    finding = by_id.get(metric.finding_id)
    if finding is None:
        problems.append(f"signature metric: finding {metric.finding_id} does not exist")
    elif metric.value_key not in finding.values:
        problems.append(f"signature metric: {metric.finding_id} has no value named {metric.value_key!r}; "
                        f"its values are {', '.join(finding.values) or 'none'}")
    elif not _numeric(finding.values[metric.value_key]):
        problems.append(f"signature metric: {metric.finding_id}.{metric.value_key} is not a number")

    if SENTENCE_BREAK.search(outline.thesis.strip()):
        problems.append("the thesis must be one sentence")

    texts = [("the thesis", outline.thesis)]
    for n, theme in enumerate(outline.themes, 1):
        texts += [(f"theme {n} title", theme.title), (f"theme {n} summary", theme.summary)]
    texts += [(f"the {s.id} goal", s.goal) for s in outline.sections]
    for where, text in texts:
        numbers = find_numbers(text)
        if numbers:
            problems.append(f"{where} contains numbers ({', '.join(n.text for n in numbers)}); "
                            "describe in words instead")
    return problems


def tidy(outline: Outline) -> Outline:
    """Remove duplicate IDs, use the standard section titles, put sections in report order."""
    order = {sid: n for n, sid in enumerate(OUTLINE_SECTIONS)}
    themes = [t.model_copy(update={"finding_ids": list(dict.fromkeys(t.finding_ids))}) for t in outline.themes]
    sections = sorted(
        (s.model_copy(update={"title": SECTION_TITLES[s.id], "finding_ids": list(dict.fromkeys(s.finding_ids))})
         for s in outline.sections),
        key=lambda s: order[s.id])
    return outline.model_copy(update={"themes": themes, "sections": sections})


def finding_for_model(f) -> dict:
    """What the model sees of a normalized finding."""
    return {"id": f.id, "product": f.product, "statement": f.statement, "values": f.values,
            "direction": f.direction, "data_gap": f.data_gap,
            "techniques": [f"{m.technique_id} {m.name}" for m in f.attack_techniques],
            "sector": f.sector, "severity": f.severity, "related_findings": f.related_findings}


def make_synthesizer(llm=None):
    """Build the synthesizer node. Without an llm, the client comes from agents.llm at run time."""

    def synthesizer(state: dict) -> dict:
        findings = state["normalized"]
        if not findings:
            raise ValueError("no findings to build an outline from")
        from agents.llm import get_llm
        model = llm or get_llm()

        year = state["year"]
        message = "Findings:\n" + json.dumps([finding_for_model(f) for f in findings],
                                             ensure_ascii=False, separators=(",", ":"))
        if state.get("outline_feedback") and state.get("outline"):
            message += ("\n\nA reviewer rejected your previous outline:\n"
                        + state["outline"].model_dump_json()
                        + f"\n\nReviewer's comment: {state['outline_feedback']}\n"
                        "Write a new outline that addresses the comment.")
        messages = [SystemMessage(load_prompt("synthesizer", year=year, previous_year=year - 1)),
                    HumanMessage(message)]
        outline = tidy(complete(model, messages, Outline, check=lambda o: check_outline(o, findings)))
        save(state["run_dir"], f"outline_{next_version(state['run_dir'], 'outline')}.json", outline)
        return {"outline": outline}

    return synthesizer


synthesizer = make_synthesizer()
