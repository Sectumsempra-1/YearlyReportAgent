"""Deterministic number and tag checks for report sections (docs/SPEC.md 9).

Plain code, no model. For one section:

- every number (text_numbers.py grammar) must be followed directly by a
  finding tag, e.g. `rose 12.4% [F-007]`; only spaces or a closing bracket
  may come between them. Years, year-months, ATT&CK IDs, digits in tags and
  numbered-list markers are not numbers.
- the number must match the finding: the cited tool call is re-run and the
  number compared with the value at each of the finding's key paths (and
  with the call's numeric arguments, like the 10 in "top 10"), rounded
  half-up to the precision shown. Signs are ignored; the wording check
  judges direction.
- every tag must point to a finding assigned to the section
- in the recommendations section, one bullet per recommendation and each
  bullet tagged

Across sections: the same value of the same finding (same key path) must be
quoted the same way everywhere (check_consistency).

Every problem is a VerificationError: the sentence, the problem and, where
there is one, the expected value. These go back to the writer.
"""

import json
import re
from dataclasses import dataclass
from decimal import Decimal

from agents.finding_check import FUNCTIONS, resolve
from agents.state import REPORT_ORDER, Section, VerificationError, VerificationResult
from text_numbers import Number, find_numbers, matches

TAG_RE = re.compile(r"\[(F-\d{3,}(?:\s*,\s*F-\d{3,})*)\]")
TAG_AFTER_RE = re.compile(r"[ \t]*[)\]]?[ \t]*\[(F-\d{3,}(?:\s*,\s*F-\d{3,})*)\]")
LIST_MARKER_RE = re.compile(r"^([ \t]*)\d+[.)](?=[ \t])", re.M)
BULLET_RE = re.compile(r"^[ \t]*[-*+][ \t]+")
SENTENCE_END_RE = re.compile(r"(?<=[.!?])\s+|\n+")


@dataclass(frozen=True)
class Quote:
    """A number in a section that matched a finding value."""
    section_id: str
    finding_id: str
    key: str            # the key name in the finding's values, or "param:<name>"
    value: Decimal      # as written (absolute)
    places: int
    text: str
    sentence: str


# --- helpers --------------------------------------------------------------------------------------

def sentence_at(text: str, pos: int) -> str:
    """The sentence (or line) of `text` that contains position `pos`."""
    start = 0
    for m in SENTENCE_END_RE.finditer(text):
        if m.start() >= pos:
            return text[start:m.start()].strip()
        start = m.end()
    return text[start:].strip()


def _scan_text(markdown: str) -> str:
    """Text to look for numbers in: numbered-list markers blanked out (same length)."""
    return LIST_MARKER_RE.sub(lambda m: m.group(1) + " " * (len(m.group()) - len(m.group(1))), markdown)


def _ids(group: str) -> list[str]:
    return [fid.strip() for fid in group.split(",")]


class SourceCache:
    """Re-runs cited tool calls once per (function, params)."""

    def __init__(self):
        self._results: dict[str, dict | Exception] = {}

    def result(self, finding):
        key = json.dumps([finding.source.function, finding.source.params], sort_keys=True, default=str)
        if key not in self._results:
            try:
                self._results[key] = FUNCTIONS[finding.source.function](**finding.source.params)
            except Exception as exc:  # reported per number
                self._results[key] = exc
        return self._results[key]

    def candidates(self, finding) -> list[tuple[str, object]]:
        """(key, current value) for each key path, plus numeric call arguments."""
        result = self.result(finding)
        if isinstance(result, Exception):
            return []
        out = []
        for key, path in finding.source.key_paths.items():
            try:
                out.append((key, resolve(result, path)))
            except (KeyError, IndexError, ValueError, TypeError):
                continue
        out += [(f"param:{k}", v) for k, v in finding.source.params.items()]
        return out


def _describe(finding, cache: SourceCache) -> str:
    shown = [f"{k}={v}" for k, v in cache.candidates(finding)
             if not k.startswith("param:") and isinstance(v, (int, float)) and not isinstance(v, bool)]
    return ", ".join(shown) or "no numeric values"


# --- one section --------------------------------------------------------------------------------------

def check_section(section: Section, findings: dict, cache: SourceCache | None = None
                  ) -> tuple[list[VerificationError], list[Quote]]:
    """Check one section against its findings (id -> finding: exactly the ones assigned to it).

    Returns the problems and the quotes (matched numbers) for the consistency check.
    """
    cache = cache or SourceCache()
    text = section.markdown
    errors: list[VerificationError] = []
    quotes: list[Quote] = []

    def error(pos: int, problem: str, expected: str | None = None):
        errors.append(VerificationError(sentence=sentence_at(text, pos), problem=problem, expected=expected))

    # tags must point to this section's findings
    reported = set()
    for m in TAG_RE.finditer(text):
        for fid in _ids(m.group(1)):
            if fid not in findings and fid not in reported:
                reported.add(fid)
                error(m.start(), f"{fid} is not one of this section's findings",
                      f"one of {', '.join(sorted(findings)) or 'none'}")

    # every number tagged, and matching its finding
    for number in find_numbers(_scan_text(text)):
        tag = TAG_AFTER_RE.match(text, number.end)
        if not tag:
            error(number.start, f"the number {number.text} has no finding tag directly after it",
                  "a tag like [F-001] right after the number")
            continue
        cited = [fid for fid in _ids(tag.group(1)) if fid in findings]
        if not cited:
            continue  # the unassigned tag is already reported
        hits = []
        for fid in cited:
            finding = findings[fid]
            if isinstance(cache.result(finding), Exception):
                error(number.start, f"{fid}'s source {finding.source.function} could not be re-run: "
                                    f"{cache.result(finding)}")
                hits = None
                break
            hits += [(fid, key) for key, value in cache.candidates(finding) if matches(number, value)]
        if hits is None:
            continue
        if not hits:
            expected = "; ".join(f"{fid}: {_describe(findings[fid], cache)}" for fid in cited)
            error(number.start, f"{number.text} does not match {', '.join(cited)}", expected)
            continue
        sentence = sentence_at(text, number.start)
        quotes += [Quote(section.id, fid, key, number.value, number.places, number.text, sentence)
                   for fid, key in hits]

    if section.id == "recommendations":
        errors += _check_recommendations(text)
    return errors, quotes


def _check_recommendations(text: str) -> list[VerificationError]:
    """One bullet per recommendation; every bullet has at least one finding tag."""
    bullets, current = [], None
    for line in text.splitlines():
        if BULLET_RE.match(line):
            current = [line]
            bullets.append(current)
        elif current is not None and line.strip() and line[:1] in " \t":
            current.append(line)   # continuation of the bullet
        else:
            current = None
    if not bullets:
        return [VerificationError(sentence=text.strip()[:200], problem="the recommendations are not bullets",
                                  expected="one '- ' bullet per recommendation")]
    errors = []
    for lines in bullets:
        bullet = " ".join(l.strip() for l in lines)
        if not TAG_RE.search(bullet):
            errors.append(VerificationError(sentence=bullet, problem="this recommendation cites no finding",
                                            expected="at least one finding tag, e.g. [F-001]"))
    return errors


def verify_section(section: Section, findings: dict, cache: SourceCache | None = None) -> VerificationResult:
    errors, _ = check_section(section, findings, cache)
    return VerificationResult(section_id=section.id, passed=not errors, errors=errors)


# --- across sections -------------------------------------------------------------------------------------

def _order(section_id: str) -> int:
    return REPORT_ORDER.index(section_id) if section_id in REPORT_ORDER else len(REPORT_ORDER)


def check_consistency(quotes: list[Quote], reference_sections: set[str] | None = None
                      ) -> dict[str, list[VerificationError]]:
    """The same key path of the same finding must be quoted the same way everywhere.

    For each value, the quote in the earliest section in report order is the
    reference (or, if reference_sections is given, the earliest of those).
    Other sections that quote it differently get an error. Returns
    section id -> errors.
    """
    by_value: dict[tuple[str, str], list[Quote]] = {}
    for q in quotes:
        if not q.key.startswith("param:"):
            by_value.setdefault((q.finding_id, q.key), []).append(q)

    problems: dict[str, list[VerificationError]] = {}
    for (fid, key), group in by_value.items():
        pool = [q for q in group if reference_sections is None or q.section_id in reference_sections] or group
        reference = min(pool, key=lambda q: _order(q.section_id))
        for q in group:
            if q.section_id == reference.section_id:
                continue
            if (q.value, q.places) != (reference.value, reference.places):
                problems.setdefault(q.section_id, []).append(VerificationError(
                    sentence=q.sentence,
                    problem=f"{q.text} quotes {fid} ({key}) differently from the "
                            f"{reference.section_id} section, which has {reference.text}",
                    expected=reference.text))
    return problems


def section_quotes(sections: dict[str, Section], findings: dict, cache: SourceCache | None = None) -> list[Quote]:
    """Quotes from several sections; findings holds every finding the sections cite."""
    cache = cache or SourceCache()
    quotes = []
    for section in sections.values():
        cited = {fid: findings[fid] for fid in section.finding_ids_used if fid in findings}
        quotes += check_section(section, cited, cache)[1]
    return quotes
