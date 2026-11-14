"""Verifier (SPEC 7.5 and 9): verify.py checks, then an LLM wording check.

STUB: every draft passes. Replaced when verify.py is built.

Input: LoopState with "draft". Output: {"verification": VerificationResult}.
The graph saves each result and routes: pass -> next, fail -> rewrite,
fourth failure -> stop.
"""

from agents.state import VerificationResult


def verifier(state: dict) -> dict:
    return {"verification": VerificationResult(section_id=state["section_id"], passed=True)}
