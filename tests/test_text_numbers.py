"""Tests for text_numbers.py: the number grammar and matching from SPEC 9.1."""

from decimal import Decimal

import pytest

from text_numbers import find_numbers, matches, unmatched


def texts(text):
    return [n.text for n in find_numbers(text)]


@pytest.mark.parametrize("text, expected", [
    ("blocked 1000 attacks", ["1000"]),
    ("blocked 1,234,567 attacks", ["1,234,567"]),
    ("rose 12.4% in total", ["12.4%"]),
    ("a change of -9.2%", ["-9.2%"]),
    ("a change of +3.0%", ["+3.0%"]),
    ("a change of −9.2%", ["−9.2%"]),
    ("from 6464 to 11663.", ["6464", "11663"]),
    ("rank 1, then rank 4", ["1", "4"]),
    ("(56490)", ["56490"]),
    ("12.5% and 0.5", ["12.5%", "0.5"]),
])
def test_numbers_found(text, expected):
    assert texts(text) == expected


@pytest.mark.parametrize("text", [
    "in 2026",                        # year
    "between 2025 and 2026",
    "peak in 2026-03",                # year-month
    "rose 12.4% [F-007]",             # the tag's digits (12.4% itself is found, tested below)
    "mapped to T1566.001 and T1190",  # ATT&CK IDs
    "Win32/Kryptik.gen",              # part of a name
    "x64 hosts on the 3rd day",       # attached to letters
    "see F-001",                      # an ID, not a minus number
    "version 1.2.3",                  # not a single number
])
def test_not_counted(text):
    found = texts(text)
    assert found in ([], ["12.4%"]), found


def test_tags_are_ignored_but_numbers_before_them_are_found():
    assert texts("rose 12.4% [F-007] and 3 [F-001, F-002]") == ["12.4%", "3"]


def test_year_with_decimals_or_percent_is_a_number():
    assert texts("2026.5 and 2026% and 2,026") == ["2026.5", "2026%", "2,026"]


def test_parsed_value_and_places():
    [n] = find_numbers("-1,234.50%")
    assert (n.value, n.places) == (Decimal("1234.50"), 2)


@pytest.mark.parametrize("text, value, ok", [
    ("12.4%", 12.4, True),
    ("12.4%", 12.43, True),        # rounded to the precision shown
    ("12%", 12.4, True),
    ("12.4%", 12.45, False),       # 12.45 rounds half-up to 12.5
    ("12.5%", 12.45, True),
    ("9.2%", -9.2, True),          # sign ignored
    ("-9.2%", 9.2, True),
    ("1,000", 1000, True),
    ("1000", 1000.0, True),
    ("1000", 1001, False),
    ("1", True, False),            # booleans are not numbers
    ("1", "1", False),             # nor are strings
    ("0", None, False),
])
def test_matches(text, value, ok):
    [n] = find_numbers(text)
    assert matches(n, value) is ok


def test_unmatched():
    text = "rose 80.4% from 6464 to 11663, now rank 1 in 2026"
    assert [n.text for n in unmatched(text, [80.4, 6464, 11663])] == ["1"]
    assert unmatched(text, [80.4, 6464, 11663, 1]) == []
