"""Tests for eval/score.py with hand-written reports. Run with: pytest eval

Evaluation code: these tests know the planted patterns (rule 8).
"""

import io
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import ingest  # noqa: E402
import report_tools as rt  # noqa: E402
import score  # noqa: E402

OVERCOUNT = ("Summed across products. One attack can be seen by more than one product "
             "(e.g. email gateway and EDR), so this may overcount attacks.")


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    assert ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    return db


@pytest.fixture(autouse=True)
def db(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


@pytest.fixture(scope="module")
def t(real_db):
    import os
    old = os.environ.get("REPORT_DB")
    os.environ["REPORT_DB"] = str(real_db)
    try:
        return score.Truth.compute(2026)
    finally:
        if old is None:
            del os.environ["REPORT_DB"]
        else:
            os.environ["REPORT_DB"] = old


class FakeJudge:
    def __init__(self, answer=True):
        self.answer, self.questions, self.calls = answer, [], []

    def ask(self, question, excerpt):
        self.questions.append((question, excerpt))
        return self.answer


def good_report(t) -> str:
    c = t.changes
    return f"""# Yearly security report 2026

Compared with 2025.

## Executive summary

**Credential theft and a new stealer defined the year.**

## Product performance

Total blocked attacks across all products fell {abs(t.total_pct)}% [F-001], while most attack types rose.
{OVERCOUNT}

Brute-force attempts fell {abs(c['brute_force'])}% [F-002], the largest category, which explains the overall drop.

Phishing rose {c['phishing']}% [F-003], with a spike in March.

Credential theft rose {c['credential_theft']}% [F-004], consistent with the info stealer LummaStealer.

Ransomware fell {abs(c['ransomware'])}% [F-005].

## Top malware

LummaStealer is new this year and is now the top family [F-006], ahead of AgentTesla.

Akira is new [F-007] and now ranks ahead of LockBit.

Win32/Kryptik.gen has no family mapping and is reported as a data gap [F-008].

## Source countries

Brazil rose from rank {t.countries['BR']['previous_rank']} [F-009] to rank {t.countries['BR']['rank']} [F-009].
Countries come from IP geolocation, not attribution of the attacker.

## Trends

Energy is the most targeted sector with {t.sectors['Energy']['share_pct']}% [F-010] of attacks.
{OVERCOUNT}

## Recommendations

- Protect credentials [F-004].

## Methodology and data gaps

- {OVERCOUNT}
"""


def write_run(tmp_path, report: str, cross_product_ids=("F-001", "F-010")) -> Path:
    run = tmp_path / "run"
    run.mkdir(parents=True)
    (run / "report.md").write_text(report, encoding="utf-8")
    normalized = [{"id": fid, "caveats": [OVERCOUNT] if fid in cross_product_ids else []}
                  for fid in (f"F-{n:03d}" for n in range(1, 11))]
    (run / "normalized.json").write_text(json.dumps(normalized), encoding="utf-8")
    return run


def results(run: Path, t, judge=None):
    report = score.Report.load(run)
    judge = judge or FakeJudge()
    out = {}
    for check in score.PATTERNS:
        r = check(report, t, judge, run) if check is score.p9_overcount else check(report, t, judge)
        out[r.number] = r
    return out


# --- the truth agrees with the answer key -------------------------------------------------------------------

def test_truth_matches_the_answer_key(t):
    assert round(t.total_pct) == -6
    assert round(t.changes["brute_force"]) == -29 and round(t.changes["phishing"]) == 83
    assert round(t.changes["ransomware"]) == -9 and round(t.changes["credential_theft"]) == 80
    assert t.phishing_peak == "March"
    assert t.malware["LummaStealer"]["rank"] == 1 and t.malware["LummaStealer"]["new_this_year"]
    assert t.previous_top_family == "AgentTesla"
    assert t.malware["Akira"]["new_this_year"] and t.malware["Akira"]["rank"] < t.malware["LockBit"]["rank"]
    assert (t.countries["BR"]["previous_rank"], t.countries["BR"]["rank"]) == (10, 3)
    assert t.sectors["Energy"]["rank"] == 1 and round(t.sectors["Energy"]["share_pct"]) == 34
    assert t.unmapped == ["Win32/Kryptik.gen"]


# --- a good report scores full marks ----------------------------------------------------------------------------

def test_good_report_gets_full_marks(tmp_path, t):
    res = results(write_run(tmp_path, good_report(t)), t)
    for n, r in res.items():
        assert r.points == r.max_points, (n, r.notes)


def test_total_and_printout(tmp_path, t, capsys, monkeypatch):
    run = write_run(tmp_path, good_report(t))
    s = score.score_run(run, use_llm=False)
    assert s["points"] == s["max_points"] and s["score_pct"] == 100.0
    score.print_score(s)
    out = capsys.readouterr().out
    assert "Total:" in out and " 1  Total blocked fell" in out


# --- typical failures ------------------------------------------------------------------------------------------

def test_only_saying_attacks_went_down_misses_pattern_1(tmp_path, t):
    report = good_report(t).replace(
        f"Brute-force attempts fell {abs(t.changes['brute_force'])}% [F-002], the largest category, "
        "which explains the overall drop.", "")
    r = results(write_run(tmp_path, report), t, FakeJudge(answer=False))[1]
    assert r.found and not r.correct


def test_judge_decides_pattern_1(tmp_path, t):
    judge = FakeJudge(answer=False)
    r = results(write_run(tmp_path, good_report(t)), t, judge)[1]
    assert not r.correct and "brute-force" in judge.questions[0][0]


def test_wrong_direction_is_not_correct(tmp_path, t):
    report = good_report(t).replace(f"Phishing rose {t.changes['phishing']}%", f"Phishing fell {t.changes['phishing']}%")
    r = results(write_run(tmp_path, report), t)[2]
    assert r.found and not r.correct


def test_wrong_number_is_not_found(tmp_path, t):
    report = good_report(t).replace(f"rose {t.changes['phishing']}%", "rose 50.0%")
    assert not results(write_run(tmp_path, report), t)[2].found


def test_missing_spike_month(tmp_path, t):
    report = good_report(t).replace(", with a spike in March", "")
    r = results(write_run(tmp_path, report), t)[2]
    assert r.found and not r.correct


def test_lumma_not_called_new(tmp_path, t):
    report = good_report(t).replace("LummaStealer is new this year and is now the top family",
                                    "LummaStealer is the top family")
    r = results(write_run(tmp_path, report), t)[3]
    assert r.found and not r.correct


def test_akira_without_lockbit(tmp_path, t):
    report = good_report(t).replace(" and now ranks ahead of LockBit", "")
    r = results(write_run(tmp_path, report), t)[4]
    assert r.found and not r.correct


def test_credential_theft_link_uses_judge_when_keywords_missing(tmp_path, t):
    report = good_report(t).replace(", consistent with the info stealer LummaStealer", "")
    judge = FakeJudge(answer=False)
    r = results(write_run(tmp_path, report), t, judge)[5]
    assert r.found and not r.correct and judge.questions
    assert results(write_run(tmp_path / "b", report), t, FakeJudge(answer=True))[5].correct


def test_geolocation_caveat_missing(tmp_path, t):
    report = good_report(t).replace("Countries come from IP geolocation, not attribution of the attacker.", "")
    r = results(write_run(tmp_path, report), t)[6]
    assert r.correct and r.caveat is False and r.points == 2


def test_overcount_caveat_must_be_in_the_section(tmp_path, t):
    report = good_report(t).replace(f"of attacks.\n{OVERCOUNT}", "of attacks.")
    res = results(write_run(tmp_path, report), t)
    assert res[7].caveat is False          # Energy's section lacks the caveat
    assert not res[9].correct and "Trends" in res[9].notes[1]


def test_kryptik_guessed_family_is_not_flagged(tmp_path, t):
    report = good_report(t).replace("Win32/Kryptik.gen has no family mapping and is reported as a data gap",
                                    "Win32/Kryptik.gen is a variant of Emotet")
    r = results(write_run(tmp_path, report), t)[8]
    assert r.found and not r.correct


def test_kryptik_dropped_silently(tmp_path, t):
    report = good_report(t).replace("Win32/Kryptik.gen has no family mapping and is reported as a data gap [F-008].", "")
    assert not results(write_run(tmp_path, report), t)[8].found


def test_summed_figures_without_the_caveat(tmp_path, t):
    report = good_report(t).replace(OVERCOUNT, "")
    r = results(write_run(tmp_path, report), t)[9]
    assert not r.correct


def test_reporting_per_product_only_avoids_the_trap(tmp_path, t):
    report = good_report(t).replace(OVERCOUNT, "")
    r = results(write_run(tmp_path, report, cross_product_ids=()), t)[9]   # no summed figures used
    assert r.found and r.correct and "reports per product only: True" in r.notes


def test_ingestion_pattern(tmp_path, t):
    r = results(write_run(tmp_path, good_report(t)), t)[10]
    assert r.found and r.correct


def test_missing_report(tmp_path):
    with pytest.raises(FileNotFoundError, match="did not produce a report"):
        score.score_run(tmp_path, use_llm=False)
