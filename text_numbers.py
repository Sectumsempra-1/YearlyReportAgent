"""Find numbers in text and match them to known values (docs/SPEC.md 9.1).

Used by the analyst's statement check, and by verify.py for report sections.
Standard library only.

What counts as a number: digits, optionally with `,` thousands separators, a
decimal point, a leading sign and a trailing `%`. Not counted:

- years 2000-2099 written alone ("in 2026")
- year-month dates ("2026-03")
- digits inside finding tags ("[F-007]") and ATT&CK technique IDs ("T1566.001")
- digits that are part of a word or name ("Win32", "x64", "3rd")

A number matches a value if the value, rounded half-up to the number of
decimals shown in the text, equals the number. Signs are ignored ("fell 9.2%"
matches -9.2); whether the wording fits the sign is the wording check's job.
"""

import re
from dataclasses import dataclass
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

# Spans removed before looking for numbers.
TAG_RE = re.compile(r"\[F-\d{3,}(?:\s*,\s*F-\d{3,})*\]")
TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
YEAR_MONTH_RE = re.compile(r"\b20\d\d-(?:0[1-9]|1[0-2])\b")

NUMBER_RE = re.compile(
    r"(?<![\w/.\-+])"                      # not part of a word, path or longer number
    r"(?P<sign>[-+−])?"
    r"(?P<digits>\d{1,3}(?:,\d{3})+|\d+)"
    r"(?P<decimals>\.\d+)?"
    r"(?P<pct>%)?"
    r"(?![\w/]|\.\d)"                      # not followed by letters ("3rd") or more digits ("1.2.3")
)
SIGN_AFTER_WORD_RE = re.compile(r"\w$")
YEAR_RE = re.compile(r"20\d\d")


@dataclass(frozen=True)
class Number:
    text: str        # as written, e.g. "-1,234.5%"
    value: Decimal   # absolute value, e.g. 1234.5
    places: int      # decimals shown, e.g. 1
    start: int
    end: int


def _blank(text: str, pattern: re.Pattern) -> str:
    return pattern.sub(lambda m: " " * len(m.group()), text)


def find_numbers(text: str) -> list[Number]:
    """Every number in the text that must be backed by a value, in order."""
    scrubbed = text
    for pattern in (TAG_RE, TECHNIQUE_RE, YEAR_MONTH_RE):
        scrubbed = _blank(scrubbed, pattern)
    numbers = []
    for m in NUMBER_RE.finditer(scrubbed):
        sign, digits, decimals, pct = m.group("sign"), m.group("digits"), m.group("decimals"), m.group("pct")
        if sign and SIGN_AFTER_WORD_RE.search(scrubbed[:m.start()]):
            continue  # "F-001" style: a hyphen after a word is not a minus sign
        if not sign and not decimals and not pct and YEAR_RE.fullmatch(digits):
            continue  # a year
        value = Decimal(digits.replace(",", "") + (decimals or ""))
        numbers.append(Number(m.group(), value, len(decimals) - 1 if decimals else 0, m.start(), m.end()))
    return numbers


def _as_decimal(value) -> Decimal | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return abs(Decimal(str(value)))
    except InvalidOperation:
        return None


def matches(number: Number, value) -> bool:
    """True if `value`, rounded to the decimals shown, equals the number (ignoring sign)."""
    d = _as_decimal(value)
    if d is None:
        return False
    return d.quantize(Decimal(1).scaleb(-number.places), rounding=ROUND_HALF_UP) == number.value


def unmatched(text: str, values) -> list[Number]:
    """Numbers in the text that match none of the given values."""
    values = list(values)
    return [n for n in find_numbers(text) if not any(matches(n, v) for v in values)]
