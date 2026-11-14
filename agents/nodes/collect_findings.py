"""Collect findings from all analysts (SPEC 7.1b). Code, no model.

- orders drafts stably and assigns IDs F-001, F-002, ...
- re-runs each cited tool call and copies its caveats into the finding
- sets direction from the cited change: "new" if the item is new this year or
  the previous value is 0, "flat" if pct_change is between -1.0 and 1.0,
  otherwise "up" or "down"; "flat" when no change is cited
- drops (and logs) drafts whose cited call fails
"""

import json

from agents.finding_check import FUNCTIONS, resolve
from agents.runs import save
from agents.state import Finding, FindingDraft

FLAT_BAND = 1.0


def direction(result: dict, key_paths: dict[str, str]) -> str:
    for path in key_paths.values():
        parent_path = path.rsplit(".", 1)[0] if "." in path else ""
        try:
            parent = resolve(result, parent_path) if parent_path else result
        except (KeyError, IndexError, TypeError, ValueError):
            continue
        if not isinstance(parent, dict):
            continue
        if parent.get("new_this_year") is True:
            return "new"
        for prev_key in ("previous", "previous_volume"):
            if parent.get(prev_key) == 0:
                return "new"
        pct = parent.get("pct_change")
        if isinstance(pct, (int, float)):
            if -FLAT_BAND <= pct <= FLAT_BAND:
                return "flat"
            return "up" if pct > 0 else "down"
    return "flat"


def _order(d: FindingDraft):
    return (d.product == "ALL", d.product, d.source.function,
            json.dumps(d.source.params, sort_keys=True, default=str), d.statement)


def collect_findings(state: dict) -> dict:
    findings, dropped = [], []
    for draft in sorted(state.get("drafts", []), key=_order):
        try:
            result = FUNCTIONS[draft.source.function](**draft.source.params)
        except Exception as exc:  # bad params: the finding cannot be traced
            dropped.append({"draft": draft, "reason": f"{type(exc).__name__}: {exc}"})
            continue
        findings.append(Finding(
            **{**draft.model_dump(), "caveats": result["caveats"]},  # the tool's exact caveats
            id=f"F-{len(findings) + 1:03d}",
            direction=direction(result, draft.source.key_paths),
        ))
    save(state["run_dir"], "findings.json", findings)
    if dropped:
        save(state["run_dir"], "findings_dropped.json", dropped)
    return {"findings": findings}
