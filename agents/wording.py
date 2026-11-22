"""The LLM wording check (docs/SPEC.md 9): do the words match the data?

Runs after verify.py's code checks pass. The model sees the section's text
and, for each cited finding, its values, direction and what its values
measure (the first line of the source tool's description). It returns
sentences whose words contradict the data: "rose" for a fall, "the top"
for rank 2, "blocked" for a count of all actions, and so on.

The check runs RUNS times and keeps only issues that every run reports. Code
also keeps an issue only if the model marks it as a contradiction, states a
problem, and quotes a sentence that is in the section and contradicting words
that are in that sentence. Everything else is dropped (and saved with the
reason), so noise cannot send a section back for a rewrite.
"""

import inspect
import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import Field

from agents.finding_check import FUNCTIONS
from agents.prompt_loader import load_prompt
from agents.state import Model, Section, VerificationError
from agents.structured import StructuredOutputError, complete

log = logging.getLogger(__name__)

# Spotting contradictions between words and values is a simple judgment; this
# keeps each check short. Reasoning made other nodes slow on local hardware.
REASONING_EFFORT = "none"

# Without reasoning, the model's real contradictions come back every time, but
# on long sections it adds a different spurious issue on each run. An issue
# is kept only if every run reports it (same sentence and words).
RUNS = 2


class WordingIssue(Model):
    sentence: str
    words: str = ""          # the exact words that contradict the data
    contradiction: bool = True
    problem: str = ""
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
    # No statements: they are the analyst's wording, and the check would copy
    # their mistakes. Values, direction and what is measured are the data.
    cited = [{"id": f.id, "values": f.values, "direction": f.direction,
              "measures": measures(f.source.function)} for f in findings]
    return ("Section text:\n" + section.markdown + "\n\nFindings it cites:\n"
            + json.dumps(cited, ensure_ascii=False, separators=(",", ":")))


def why_dropped(issue: WordingIssue, text: str) -> str:
    """Why an issue is not kept, or "" to keep it."""
    if not issue.contradiction:
        return "the model marked it as not a contradiction"
    if not issue.problem.strip():
        return "no problem stated"
    sentence = _normalize(issue.sentence)
    if not sentence or sentence not in text:
        return "its sentence is not in the section"
    words = _normalize(issue.words)
    if not words or words not in sentence:
        return "its contradicting words are not in the sentence"
    return ""


def _one_run(model, messages: list, n: int, failures: list[str]):
    """One wording check. A server error (e.g. Ollama aborting a reply that repeats itself)
    is retried once; if it fails again the run is skipped and the others decide."""
    for attempt in (1, 2):
        try:
            return complete(model, list(messages), WordingOutput)
        except StructuredOutputError:
            raise   # invalid output twice: the usual rule, fail clearly
        except Exception as exc:   # server or connection error
            log.warning("wording check run %d, try %d failed: %s", n, attempt, exc)
            if attempt == 2:
                failures.append(f"run {n}: {type(exc).__name__}: {exc}")
    return None


def _key(issue: WordingIssue) -> tuple[str, str]:
    return _normalize(issue.sentence), _normalize(issue.words)


def check_wording(llm, section: Section, findings: list, runs: int = RUNS
                  ) -> tuple[list[VerificationError], list[dict]]:
    """Run the check `runs` times; keep issues that every run reports (same sentence and words).

    Returns (issues kept, issues dropped with the reason).
    """
    messages = [SystemMessage(load_prompt("wording_check")), HumanMessage(wording_message(section, findings))]
    # JSON mode: the server only produces valid JSON. Without it this short,
    # no-reasoning call occasionally returned broken JSON twice in a row.
    model = llm.bind(response_format={"type": "json_object"})
    text = _normalize(section.markdown)
    dropped: list[dict] = []
    per_run: list[dict[tuple, WordingIssue]] = []
    failures: list[str] = []
    for n in range(1, runs + 1):
        output = _one_run(model, messages, n, failures)
        if output is None:
            continue
        valid = {}
        for issue in output.issues:
            reason = why_dropped(issue, text)
            if reason:
                dropped.append({**issue.model_dump(), "dropped_because": reason})
                log.info("wording check: dropped an issue (%s): %r", reason, issue.sentence)
            else:
                valid.setdefault(_key(issue), issue)
        per_run.append(valid)

    if not per_run:
        raise RuntimeError("wording check: every run failed: " + "; ".join(failures))
    agreed = set(per_run[0]).intersection(*per_run[1:])
    kept = []
    for key, issue in per_run[0].items():
        if key in agreed:
            kept.append(VerificationError(sentence=issue.sentence,
                                          problem=f"wording: {_short(issue.words)!r}: {_short(issue.problem)}",
                                          expected=_short(issue.expected) or None))
    for n, run in enumerate(per_run, 1):
        for key, issue in run.items():
            if key not in agreed:
                dropped.append({**issue.model_dump(), "dropped_because": f"reported in run {n} only, "
                                                                          f"not by every one of {runs} runs"})
    return kept, dropped
