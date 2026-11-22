"""Executive summary (SPEC 7.6). No tools.

Input (LoopState, built by the graph's summary_payload): the approved
outline, the verified sections, the findings used in them, and on a
rejected report the reviewer's comment and the previous summary. On a
failed verification, the previous draft and its errors.

The model returns the parts as separate fields; code checks the structure
and builds the Markdown in a fixed order, under the outline's theme titles:

    **<thesis>**
    ### Headline numbers        5-8 bullets, each with a tagged number
    ### <theme 1 title> ...     one paragraph per outline theme, in order
    ### Top recommendations     bullets, each with a finding tag

A structure problem gets one retry with the problems listed. The result is
verified like any section (numbers, tags, consistency with the sections,
wording), then the graph pauses for the final approval.

Output: {"draft": Section}.
"""

import json

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import Field

from agents.nodes.section_writer import rewrite_lines, tags_in
from agents.prompt_loader import load_prompt
from agents.state import EXEC_SUMMARY_ID, OUTLINE_SECTIONS, SECTION_TITLES, Model, Section
from agents.structured import complete
from text_numbers import find_numbers

MIN_HEADLINES, MAX_HEADLINES = 5, 8


class SummaryOutput(Model):
    thesis: str = Field(min_length=1)
    headlines: list[str]
    theme_paragraphs: list[str]
    recommendations: list[str]


def check_summary(output: SummaryOutput, themes: list) -> list[str]:
    """Structure checks (SPEC 7.6). Numbers and wording are checked by the verifier."""
    problems = []
    if not MIN_HEADLINES <= len(output.headlines) <= MAX_HEADLINES:
        problems.append(f"give {MIN_HEADLINES} to {MAX_HEADLINES} headlines, not {len(output.headlines)}")
    for n, headline in enumerate(output.headlines, 1):
        if not find_numbers(headline) or not tags_in(headline):
            problems.append(f"headline {n} needs a number with its finding tag: {headline!r}")
    if len(output.theme_paragraphs) != len(themes):
        problems.append(f"give one paragraph per outline theme: {len(themes)} themes, "
                        f"{len(output.theme_paragraphs)} paragraphs")
    if not output.recommendations:
        problems.append("give at least one recommendation")
    for n, rec in enumerate(output.recommendations, 1):
        if not tags_in(rec):
            problems.append(f"recommendation {n} cites no finding: {rec!r}")
    if find_numbers(output.thesis):
        problems.append("the thesis must not contain numbers")
    return problems


def build_markdown(output: SummaryOutput, themes: list) -> str:
    parts = [f"**{output.thesis.strip()}**", "", "### Headline numbers", ""]
    parts += [f"- {h.strip()}" for h in output.headlines]
    for theme, paragraph in zip(themes, output.theme_paragraphs):
        parts += ["", f"### {theme.title}", "", paragraph.strip()]
    parts += ["", "### Top recommendations", ""]
    parts += [f"- {r.strip()}" for r in output.recommendations]
    return "\n".join(parts)


def summary_message(state: dict) -> str:
    outline = state["outline"]
    compact = {"ensure_ascii": False, "separators": (",", ":")}
    sections = state.get("verified_sections") or {}
    parts = [f"Outline thesis: {outline.thesis}", "", "Themes, most important first:"]
    parts += [f"{n}. {t.title}: {t.summary} (findings {', '.join(t.finding_ids)})"
              for n, t in enumerate(outline.themes, 1)]
    parts += ["", "The report's sections:"]
    for sid in OUTLINE_SECTIONS:
        if sid in sections:
            parts += ["", f"## {sections[sid].title}", sections[sid].markdown]
    findings = [{"id": f.id, "statement": f.statement, "values": f.values, "caveats": f.caveats,
                 "data_gap": f.data_gap} for f in state["findings"]]
    parts += ["", "Findings used in the sections:", json.dumps(findings, **compact)]
    if state.get("feedback") and state.get("draft") is not None and state.get("verification") is None:
        parts += ["", "A reviewer rejected your previous summary:", state["draft"].markdown, "",
                  f"Reviewer's comment: {state['feedback']}"]
    parts += rewrite_lines(state)
    return "\n".join(parts)


def make_exec_summary(llm=None):
    """Build the executive summary node. Without an llm, the client comes from agents.llm at run time."""

    def exec_summary(state: dict) -> dict:
        from agents.llm import get_llm
        model = llm or get_llm()   # plain model: no tools
        themes = state["outline"].themes
        year = state["year"]
        messages = [SystemMessage(load_prompt("exec_summary", year=year, previous_year=year - 1)),
                    HumanMessage(summary_message(state))]
        output = complete(model, messages, SummaryOutput, check=lambda o: check_summary(o, themes))
        markdown = build_markdown(output, themes)
        return {"draft": Section(id=EXEC_SUMMARY_ID, title=SECTION_TITLES[EXEC_SUMMARY_ID],
                                 markdown=markdown, finding_ids_used=tags_in(markdown))}

    return exec_summary


exec_summary = make_exec_summary()
