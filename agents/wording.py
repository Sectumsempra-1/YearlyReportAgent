"""The LLM wording check (docs/SPEC.md 9): do the words match the data?

Runs after verify.py's code checks pass. The model sees the section's text
and, for each cited finding, its values, direction and what its values
measure (the first line of the source tool's description). It returns
sentences whose words contradict the data: "rose" for a fall, "the top"
for rank 2, "blocked" for a count of all actions, and so on.

Code keeps only issues whose sentence really appears in the section, so an
invented quote cannot send a section back for a rewrite.
"""

import inspect
import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import Field

from agents.finding_check import FUNCTIONS
from agents.prompt_loader import load_prompt
from agents.state import Model, Section, VerificationError
from agents.structured import complete

log = logging.getLogger(__name__)

# Spotting contradictions between words and values is a simple judgment; this
# keeps each check short. Reasoning made other nodes slow on local hardware.
REASONING_EFFORT = "none"


class WordingIssue(Model):
    sentence: str
    problem: str
    expected: str = ""


class WordingOutput(Model):
    issues: list[WordingIssue] = Field(default_factory=list)


def _normalize(text: str) -> str:
    return " ".join(text.replace("*", "").split()).lower()


MAX_PROBLEM_CHARS = 300  # a safety net: the prompt asks for one short sentence


def _short(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_PROBLEM_CHARS else text[:MAX_PROBLEM_CHARS - 1].rstrip() + "…"


def measures(function: str) -> str:
    doc = inspect.getdoc(FUNCTIONS[function]) or ""
    return doc.splitlines()[0] if doc else function


def wording_message(section: Section, findings: list) -> str:
    cited = [{"id": f.id, "statement": f.statement, "values": f.values, "direction": f.direction,
              "measures": measures(f.source.function)} for f in findings]
    return ("Section text:\n" + section.markdown + "\n\nFindings it cites:\n"
            + json.dumps(cited, ensure_ascii=False, separators=(",", ":")))


def check_wording(llm, section: Section, findings: list) -> tuple[list[VerificationError], list[dict]]:
    """Return (issues kept, issues dropped because their sentence is not in the section)."""
    messages = [SystemMessage(load_prompt("wording_check")), HumanMessage(wording_message(section, findings))]
    # JSON mode: the server only produces valid JSON. Without it this short,
    # no-reasoning call occasionally returned broken JSON twice in a row.
    output = complete(llm.bind(response_format={"type": "json_object"}), messages, WordingOutput)
    text = _normalize(section.markdown)
    kept, dropped = [], []
    for issue in output.issues:
        quoted = _normalize(issue.sentence)
        if quoted and quoted in text:
            kept.append(VerificationError(sentence=issue.sentence, problem=f"wording: {_short(issue.problem)}",
                                          expected=_short(issue.expected) or None))
        else:
            dropped.append(issue.model_dump())
            log.warning("wording check: dropped an issue whose sentence is not in the section: %r",
                        issue.sentence)
    return kept, dropped
