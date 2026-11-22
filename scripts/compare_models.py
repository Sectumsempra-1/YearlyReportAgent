"""Run the pipeline once per model and compare score, run time and retries.

Usage:
    set EVAL_MODELS=qwen3.5:9b,qwen3:8b,gpt-oss:20b          (PowerShell: $env:EVAL_MODELS="...")
    python scripts/compare_models.py --year 2026
    python scripts/compare_models.py --year 2026 --no-llm    # score without the LLM judge

For each model in EVAL_MODELS (comma-separated), runs `run_report.py` in its
own process with LLM_MODEL set to that model. Both approval pauses are
approved automatically, so runs can go unattended. Each report is then scored
with eval/score.py; the judge model is EVAL_JUDGE_MODEL (or LLM_MODEL from
.env), the same for every run, so scores are comparable.

Prints a table: status, score, run time and verification retries (rewrites
after a failed verification or a cross-section conflict). Also writes it to
runs/compare_<timestamp>.json.

Needs the database (python ingest.py) and the ATT&CK data
(python scripts/fetch_attack.py). A full run per model can take an hour or more.
"""

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = ROOT / "runs"
RUN_LINE_RE = re.compile(r"^Run (\S+): (.+)$", re.M)
ATTEMPT_RE = re.compile(r"^section_(?P<section>.+?)(?:_round(?P<round>\d+))?_attempt(?P<attempt>\d+)\.json$")
AUTO_APPROVE = "a\n" * 20   # far more answers than a run can ask for
STATUS_BY_CODE = {0: "completed", 1: "failed", 3: "aborted", 4: "error"}


def models_from_env(value: str | None) -> list[str]:
    models = [m.strip() for m in (value or "").split(",") if m.strip()]
    return list(dict.fromkeys(models))


def run_dir_from_output(stdout: str) -> Path | None:
    m = RUN_LINE_RE.search(stdout)
    return Path(m.group(2).strip()) if m else None


def count_retries(run_dir: Path) -> dict:
    """Rewrites per section: the highest attempt number minus one, summed over rounds."""
    highest: dict[tuple[str, int], int] = {}
    for path in run_dir.glob("section_*_attempt*.json"):
        m = ATTEMPT_RE.match(path.name)
        if m:
            key = (m.group("section"), int(m.group("round") or 1))
            highest[key] = max(highest.get(key, 0), int(m.group("attempt")))
    per_section: dict[str, int] = {}
    for (section, _), attempts in highest.items():
        per_section[section] = per_section.get(section, 0) + attempts - 1
    return {"total": sum(per_section.values()), "per_section": dict(sorted(per_section.items()))}


def failed_sections(run_dir: Path) -> list[str]:
    path = run_dir / "failures.json"
    return sorted(json.loads(path.read_text(encoding="utf-8"))) if path.is_file() else []


def run_model(model: str, year: int, timeout: float | None = None) -> dict:
    """Run the pipeline with one model in its own process; approve both pauses."""
    env = {**os.environ, "LLM_MODEL": model, "PYTHONIOENCODING": "utf-8"}
    start = time.monotonic()
    try:
        proc = subprocess.run([sys.executable, str(ROOT / "run_report.py"), "--year", str(year)],
                              input=AUTO_APPROVE, capture_output=True, text=True, encoding="utf-8",
                              env=env, cwd=ROOT, timeout=timeout)
        stdout, code = proc.stdout, proc.returncode
        status = STATUS_BY_CODE.get(code, f"error (exit {code})")
        error = ""
        if status == "error":   # run_report prints the error after "Status: error"
            after = stdout.split("Status: error", 1)[-1].strip().splitlines()
            error = after[0] if after else ""
        elif code not in STATUS_BY_CODE and proc.stderr.strip():
            error = proc.stderr.strip().splitlines()[-1]
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        status, error = "timed out", f"no result after {timeout:.0f} s"
    seconds = time.monotonic() - start
    run_dir = run_dir_from_output(stdout)
    result = {"model": model, "status": status, "seconds": round(seconds), "run_dir": str(run_dir) if run_dir else None,
              "error": error, "retries": None, "failed_sections": [], "score": None}
    if run_dir and run_dir.is_dir():
        result["retries"] = count_retries(run_dir)
        result["failed_sections"] = failed_sections(run_dir)
        (run_dir / "run_report_output.txt").write_text(stdout, encoding="utf-8")
    return result


SCORER = ROOT / "eval" / "score.py"


def load_scorer():
    if not SCORER.is_file():
        raise FileNotFoundError(f"{SCORER} not found. The evaluation material is not in the repository "
                                "(eval/ is gitignored); copy it into eval/ first.")
    spec = importlib.util.spec_from_file_location("score", SCORER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def add_score(result: dict, use_llm: bool, scorer=None) -> dict:
    if result["status"] != "completed" or not result["run_dir"]:
        return result
    scorer = scorer or load_scorer()
    try:
        s = scorer.score_run(Path(result["run_dir"]), use_llm=use_llm)
        result["score"] = {"points": s["points"], "max_points": s["max_points"], "pct": s["score_pct"]}
        (Path(result["run_dir"]) / "score.json").write_text(json.dumps(s, indent=2), encoding="utf-8")
    except Exception as exc:   # scoring problems should not hide the run's other results
        result["error"] = f"scoring failed: {type(exc).__name__}: {exc}"
    return result


def format_duration(seconds: int | None) -> str:
    if seconds is None:
        return "-"
    minutes, secs = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m" if hours else f"{minutes}m{secs:02d}s"


def format_table(results: list[dict]) -> str:
    header = f"{'model':<22} {'status':<12} {'score':>13} {'time':>8} {'retries':>8}  notes"
    lines = [header, "-" * len(header)]
    for r in results:
        score = f"{r['score']['points']}/{r['score']['max_points']} ({r['score']['pct']:.0f}%)" if r["score"] else "-"
        retries = "-" if r["retries"] is None else str(r["retries"]["total"])
        notes = []
        if r["failed_sections"]:
            notes.append("failed: " + ", ".join(r["failed_sections"]))
        if r["retries"] and r["retries"]["total"]:
            notes.append("rewrites: " + ", ".join(f"{s} {n}" for s, n in r["retries"]["per_section"].items() if n))
        if r["error"]:
            notes.append(r["error"])
        lines.append(f"{r['model']:<22} {r['status']:<12} {score:>13} {format_duration(r['seconds']):>8} "
                     f"{retries:>8}  {'; '.join(notes)}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run the pipeline with each model in EVAL_MODELS and compare.")
    parser.add_argument("--year", type=int, required=True)
    parser.add_argument("--no-llm", action="store_true", help="score without the LLM judge")
    parser.add_argument("--timeout", type=float, default=None, help="seconds per run before giving up")
    args = parser.parse_args(argv)

    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
    models = models_from_env(os.environ.get("EVAL_MODELS"))
    if not models:
        print("Set EVAL_MODELS to a comma-separated list of models, e.g. qwen3.5:9b,qwen3:8b")
        return 2
    judge = os.environ.get("EVAL_JUDGE_MODEL") or os.environ.get("LLM_MODEL", "?")
    print(f"Comparing {len(models)} model(s) for {args.year}; both approvals are given automatically; "
          f"judge: {'off' if args.no_llm else judge}\n")

    try:
        scorer = load_scorer()
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 2
    results = []
    for n, model in enumerate(models, 1):
        print(f"[{n}/{len(models)}] {model} ...", flush=True)
        result = add_score(run_model(model, args.year, args.timeout), not args.no_llm, scorer)
        print(f"        {result['status']} in {format_duration(result['seconds'])}"
              + (f", run folder {result['run_dir']}" if result["run_dir"] else ""), flush=True)
        results.append(result)

    print("\n" + format_table(results))
    RUNS_ROOT.mkdir(exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = RUNS_ROOT / f"compare_{stamp}.json"
    out.write_text(json.dumps({"year": args.year, "judge": None if args.no_llm else judge, "results": results},
                              indent=2), encoding="utf-8")
    print(f"\nSaved to {out}")
    return 0 if all(r["status"] == "completed" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
