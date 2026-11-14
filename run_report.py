"""Run the report pipeline.

Usage:
    python run_report.py --year 2026

Creates runs/<run_id>/, runs the graph, and pauses twice for approval from
the command line: after the outline and before publishing. At each pause:
[a]pprove, [r]eject with a comment, or a[b]ort.

Exit code: 0 report written, 1 a section failed verification, 3 aborted.
"""

import argparse
import sqlite3
import sys
from pathlib import Path

from dotenv import load_dotenv
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.types import Command

from agents.graph import build_graph, checkpoint_serializer
from agents.runs import RUNS_ROOT, create_run_dir

PROJECT_ROOT = Path(__file__).resolve().parent
EXIT_CODES = {"completed": 0, "failed": 1, "aborted": 3}


def ask_approval(input_fn=input, out=sys.stdout) -> dict:
    """Ask until a valid answer. End of input counts as abort."""
    while True:
        try:
            answer = input_fn("[a]pprove, [r]eject with comment, a[b]ort: ").strip().lower()
        except EOFError:
            return {"decision": "abort", "comment": "end of input"}
        if answer in ("a", "approve"):
            return {"decision": "approve", "comment": ""}
        if answer in ("b", "abort"):
            return {"decision": "abort", "comment": ""}
        if answer in ("r", "reject"):
            try:
                comment = input_fn("Comment for the rewrite: ").strip()
            except EOFError:
                return {"decision": "abort", "comment": "end of input"}
            if comment:
                return {"decision": "reject", "comment": comment}
            print("A rejection needs a comment.", file=out)
            continue
        print("Please answer a, r or b.", file=out)


def run(year: int, graph, run_id: str, run_dir: Path, input_fn=input, out=sys.stdout) -> dict:
    """Run the graph to the end, asking for approval at each pause. Returns the final state."""
    config = {"configurable": {"thread_id": run_id}}
    state = graph.invoke({"year": year, "run_id": run_id, "run_dir": str(run_dir), "status": "running"},
                         config)
    while state.get("__interrupt__"):
        print("\n" + state["__interrupt__"][0].value["text"] + "\n", file=out)
        state = graph.invoke(Command(resume=ask_approval(input_fn, out)), config)
    return state


def main(argv=None, input_fn=input, out=sys.stdout, runs_root: Path = RUNS_ROOT) -> int:
    parser = argparse.ArgumentParser(description="Generate the yearly security report.")
    parser.add_argument("--year", type=int, required=True, help="report year, e.g. 2026")
    args = parser.parse_args(argv)

    load_dotenv(PROJECT_ROOT / ".env", override=False)
    run_id, run_dir = create_run_dir(runs_root)
    print(f"Run {run_id}: {run_dir}", file=out)
    conn = sqlite3.connect(run_dir / "checkpoints.db", check_same_thread=False)
    try:
        checkpointer = SqliteSaver(conn, serde=checkpoint_serializer())
        state = run(args.year, build_graph(checkpointer=checkpointer), run_id, run_dir, input_fn, out)
    finally:
        conn.close()

    status = state.get("status", "running")
    print(f"\nStatus: {status}", file=out)
    if status == "completed":
        print(f"Report: {run_dir / 'report.md'}", file=out)
    elif status == "failed":
        print(f"Sections that failed verification: {', '.join(state.get('failed', {}))}", file=out)
        print(f"Details: {run_dir / 'failures.json'}", file=out)
    return EXIT_CODES.get(status, 1)


if __name__ == "__main__":
    sys.exit(main())
