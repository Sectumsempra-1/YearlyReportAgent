"""Verifier (SPEC 7.5 and 9): verify.py's code checks first, then the LLM wording check.

For an outline section, the findings in its LoopState are exactly the ones
assigned to it, so a tag to any other finding fails. For the executive
summary they are the findings used in the verified sections (SPEC 9.1), and
its quotes must match how those sections quoted the same values.

The wording check runs only when the code checks pass: a draft that fails
them is rewritten anyway. The graph saves each result and routes: pass ->
next, fail -> back to the writer with the errors, fourth failure -> stop.

Input: LoopState with "draft". Output: {"verification": VerificationResult}.
"""

from agents.runs import save
from agents.state import VerificationResult
from agents.wording import REASONING_EFFORT, RUNS, check_wording
from verify import SourceCache, check_consistency, check_section, section_quotes


def make_verifier(llm=None, wording: bool = True, wording_runs: int = RUNS):
    """Build the verifier node. Without an llm, the client comes from agents.llm at run time.
    wording=False skips the LLM check (code checks only); wording_runs is how many times
    the wording check runs (an issue must be reported by all of them)."""

    def verifier(state: dict) -> dict:
        draft = state["draft"]
        findings = {f.id: f for f in state["findings"]}
        cache = SourceCache()
        errors, quotes = check_section(draft, findings, cache)

        verified = state.get("verified_sections") or {}
        if verified:
            others = section_quotes(verified, findings, cache)
            errors += check_consistency(others + quotes, reference_sections=set(verified)).get(draft.id, [])

        if not errors and wording:
            from agents.llm import get_llm
            model = llm or get_llm(reasoning_effort=REASONING_EFFORT)
            cited = [findings[fid] for fid in draft.finding_ids_used if fid in findings]
            errors, dropped = check_wording(model, draft, cited, wording_runs)
            if dropped:   # issues quoting sentences that are not in the section
                save(state["run_dir"], f"wording_dropped_{draft.id}_attempt{state['attempt']}.json", dropped)

        return {"verification": VerificationResult(section_id=draft.id, passed=not errors, errors=errors)}

    return verifier


verifier = make_verifier()
