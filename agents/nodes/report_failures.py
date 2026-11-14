"""Stop the run and report which sections failed verification. Code, no model."""

from agents.runs import save


def report_failures(state: dict) -> dict:
    failures = {sid: {"attempts": state.get("attempts", {}).get(sid), "errors": errors}
                for sid, errors in state.get("failed", {}).items()}
    save(state["run_dir"], "failures.json", failures)
    return {"status": "failed"}
