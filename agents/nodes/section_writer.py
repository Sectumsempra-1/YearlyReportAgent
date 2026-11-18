"""Section writer (SPEC 7.4): one per outline section, in parallel. No tools.

The graph runs one write -> verify -> retry loop per outline section, all
sections at once (agents/graph.py). This node writes one draft: it sends the
model the section's title and goal and only the findings assigned to it, and
on a rewrite also its previous draft and the verifier's errors. The model is
called without tools (rule 3).

Code sets the section's id and title, removes a leading heading that repeats
the title, and fills finding_ids_used from the
[F-xxx] tags actually in the text. The graph saves each attempt.

Input: the section's LoopState. Output: {"draft": Section}.
"""

import json
import re

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import Field

from agents.prompt_loader import load_prompt
from agents.state import Model, Section
from agents.structured import complete

TAG_RE = re.compile(r"\[(F-\d{3,}(?:\s*,\s*F-\d{3,})*)\]")


class WriterOutput(Model):
    markdown: str = Field(min_length=1)


def tags_in(markdown: str) -> list[str]:
    """Finding IDs tagged in the text, in order of first use."""
    ids = [fid.strip() for group in TAG_RE.findall(markdown) for fid in group.split(",")]
    return list(dict.fromkeys(ids))


def strip_title_heading(markdown: str, title: str) -> str:
    """Remove a leading heading that repeats the section title; code adds the title itself."""
    first, _, rest = markdown.partition("\n")
    if first.lstrip().startswith("#") and first.lstrip("# ").strip().lower() == title.strip().lower():
        return rest.strip()
    return markdown


def finding_for_writer(f) -> dict:
    """What the writer sees of a finding."""
    return {"id": f.id, "product": f.product, "statement": f.statement, "values": f.values,
            "direction": f.direction, "caveats": f.caveats, "data_gap": f.data_gap,
            "techniques": [f"{m.technique_id} {m.name}" for m in f.attack_techniques],
            "sector": f.sector, "severity": f.severity}


def writer_message(state: dict) -> str:
    compact = {"ensure_ascii": False, "separators": (",", ":")}
    parts = [f"Section: {state['title']}", f"Goal: {state['goal']}", "",
             "Findings for this section:", json.dumps([finding_for_writer(f) for f in state["findings"]],
                                                      **compact)]
    verification = state.get("verification")
    if verification is not None and not verification.passed and state.get("draft") is not None:
        parts += ["", "Your previous draft failed verification:", state["draft"].markdown, "",
                  "Problems to fix:"]
        for e in verification.errors:
            line = f"- {e.problem} (in: {e.sentence!r})"
            if e.expected:
                line += f"; expected: {e.expected}"
            parts.append(line)
    return "\n".join(parts)


def make_section_writer(llm=None, prompt_name: str = "section_writer"):
    """Build the writer node. Without an llm, the client comes from agents.llm at run time."""

    def section_writer(state: dict) -> dict:
        from agents.llm import get_llm
        model = llm or get_llm()   # plain model: no bind_tools, the writer has no tools
        year = state["year"]
        messages = [SystemMessage(load_prompt(prompt_name, year=year, previous_year=year - 1)),
                    HumanMessage(writer_message(state))]
        output = complete(model, messages, WriterOutput)
        markdown = strip_title_heading(output.markdown.strip(), state["title"])
        return {"draft": Section(id=state["section_id"], title=state["title"], markdown=markdown,
                                 finding_ids_used=tags_in(markdown))}

    return section_writer


section_writer = make_section_writer()
