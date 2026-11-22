"""Tests for scripts/compare_models.py helpers. No pipeline is run and no model is called."""

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("compare_models", ROOT / "scripts" / "compare_models.py")
cm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cm)


@pytest.mark.parametrize("value, expected", [
    ("qwen3.5:9b,qwen3:8b", ["qwen3.5:9b", "qwen3:8b"]),
    (" a , b ,, a ", ["a", "b"]),
    ("", []),
    (None, []),
])
def test_models_from_env(value, expected):
    assert cm.models_from_env(value) == expected


def test_run_dir_from_output():
    out = "Run 20261122T120000Z: C:\\proj\\runs\\20261122T120000Z\n\nOUTLINE..."
    assert cm.run_dir_from_output(out) == Path("C:\\proj\\runs\\20261122T120000Z")
    assert cm.run_dir_from_output("nothing") is None


def test_count_retries(tmp_path):
    for name in ["section_trends_attempt1.json", "section_trends_attempt2.json", "section_trends_attempt3.json",
                 "section_top_malware_attempt1.json",
                 "section_executive_summary_attempt1.json", "section_executive_summary_attempt2.json",
                 "section_executive_summary_round2_attempt1.json",
                 "section_methodology.json", "verify_trends_attempt1.json"]:
        (tmp_path / name).write_text("{}")
    assert cm.count_retries(tmp_path) == {
        "total": 3, "per_section": {"executive_summary": 1, "top_malware": 0, "trends": 2}}


def test_failed_sections(tmp_path):
    assert cm.failed_sections(tmp_path) == []
    (tmp_path / "failures.json").write_text(json.dumps({"trends": {}, "methodology": {}}))
    assert cm.failed_sections(tmp_path) == ["methodology", "trends"]


def result(model, status="completed", score=(20, 26), seconds=3725, retries=2, failed=(), error=""):
    return {"model": model, "status": status, "seconds": seconds, "run_dir": "r", "error": error,
            "failed_sections": list(failed),
            "retries": None if retries is None else {"total": retries, "per_section": {"trends": retries}},
            "score": None if score is None else {"points": score[0], "max_points": score[1],
                                                 "pct": 100 * score[0] / score[1]}}


def test_format_table():
    table = cm.format_table([
        result("qwen3.5:9b"),
        result("qwen3:8b", status="failed", score=None, seconds=1800, retries=6, failed=["trends"]),
        result("broken", status="error (exit 2)", score=None, seconds=5, retries=None, error="ValueError: x"),
    ])
    lines = table.splitlines()
    assert lines[0].split() == ["model", "status", "score", "time", "retries", "notes"]
    assert "20/26 (77%)" in lines[2] and "1h02m" in lines[2] and "rewrites: trends 2" in lines[2]
    assert "failed: trends" in lines[3] and "30m00s" in lines[3]
    assert lines[4].startswith("broken") and "error (exit 2)" in lines[4] and "ValueError: x" in lines[4]
    assert lines[4].split("error (exit 2)")[1].split()[:3] == ["-", "0m05s", "-"]   # score, time, retries


def test_failed_runs_are_not_scored():
    r = result("m", status="failed", score=None)

    class Boom:
        def score_run(self, *a, **k):
            raise AssertionError("must not score a failed run")

    assert cm.add_score(r, use_llm=False, scorer=Boom())["score"] is None


def test_scoring_errors_are_reported_not_raised(tmp_path):
    r = {**result("m", score=None), "run_dir": str(tmp_path)}

    class Broken:
        def score_run(self, *a, **k):
            raise FileNotFoundError("report.md not found")

    out = cm.add_score(r, use_llm=False, scorer=Broken())
    assert out["score"] is None and "scoring failed: FileNotFoundError" in out["error"]


def test_no_models(monkeypatch, capsys):
    monkeypatch.delenv("EVAL_MODELS", raising=False)
    monkeypatch.setattr(cm, "load_scorer", lambda: None)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: None)
    assert cm.main(["--year", "2026"]) == 2
    assert "Set EVAL_MODELS" in capsys.readouterr().out


def test_missing_scorer_is_explained(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cm, "SCORER", tmp_path / "score.py")
    monkeypatch.setenv("EVAL_MODELS", "m")
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: None)
    assert cm.main(["--year", "2026"]) == 2
    assert "Restore the eval/ folder" in capsys.readouterr().out
