"""Score a run's report against the planted patterns in eval/answer_key.md.

Usage:
    python eval/score.py runs/<run_id>            # keyword, value and LLM-judge checks
    python eval/score.py runs/<run_id> --no-llm   # keyword and value checks only
    python eval/score.py runs/<run_id> --json     # also write score.json to the run folder

For each pattern:
    found    the report mentions the pattern's subject with its key number
    correct  direction, rank, "new" and key numbers match the data
    caveat   the caveat that applies is stated in the same section (only where one applies)

Expected values are computed from the database with report_tools (the
answer key's figures are approximate). Text is matched per block: a
paragraph or a bullet. An LLM judge is used only where a pattern needs
interpretation (patterns 1 and 5); its model is EVAL_JUDGE_MODEL, or
LLM_MODEL if that is not set, so different runs can be judged by the same
model.

This is evaluation code: it knows the planted patterns. Nothing here may be
used in agent prompts or code (CLAUDE.md, rule 8).
"""

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ingest  # noqa: E402
import report_tools as rt  # noqa: E402
from text_numbers import find_numbers, matches  # noqa: E402

MONTH_NAMES = ["January", "February", "March", "April", "May", "June", "July", "August", "September",
               "October", "November", "December"]
UP = r"\b(ros[e]|rise|rising|increas\w*|grew|grow\w*|up\b|surg\w*|jump\w*|climb\w*|higher|doubl\w*)"
DOWN = r"\b(fell|fall\w*|declin\w*|decreas\w*|drop\w*|down\b|lower|reduc\w*|shrank|contract\w*)"
NEW = r"\b(new|newly|first appear\w*|emerg\w*|not seen|absent (?:last|in))"
TOP = r"(#\s*1\b|\btop\b|rank(?:ed)?\s*(?:#\s*)?1\b|\bleading\b|\bleads?\b|\bmost (?:detected|common|targeted|attacked|prevalent)\b|\bfirst place\b|\blargest\b|\bnumber one\b|\bhighest\b)"
OVERCOUNT = r"(more than one product|overcount\w*|over-count\w*|counted more than once|double[- ]count\w*|seen by (?:more than one|several|multiple) products|overstat\w*)"
GEOLOCATION = r"(geolocat\w*|not (?:the )?attribution|does not identify the attacker|vpn|prox(?:y|ies))"
UNMAPPED = r"(unmapped|no (?:common )?(?:family )?mapping|not mapped|without (?:a )?(?:family )?mapping|no family|data gap)"


# --- the report ------------------------------------------------------------------------------------

@dataclass
class Report:
    text: str
    sections: dict[str, str]     # title -> markdown

    @classmethod
    def load(cls, run_dir: Path) -> "Report":
        path = run_dir / "report.md"
        if not path.is_file():
            raise FileNotFoundError(f"{path} not found: the run did not produce a report")
        text = path.read_text(encoding="utf-8")
        sections = {}
        for chunk in re.split(r"^## ", text, flags=re.M)[1:]:
            title, _, body = chunk.partition("\n")
            sections[title.strip()] = body
        return cls(text, sections)

    def blocks(self, exclude_methodology: bool = False) -> list[tuple[str, str]]:
        """(section title, block) for every paragraph and bullet."""
        out = []
        for title, body in self.sections.items():
            if exclude_methodology and title.lower().startswith("methodology"):
                continue
            for para in re.split(r"\n\s*\n", body):
                lines = para.splitlines()
                if any(re.match(r"\s*[-*+]\s", l) for l in lines):
                    current = []
                    for line in lines:
                        if re.match(r"\s*[-*+]\s", line) and current:
                            out.append((title, " ".join(current)))
                            current = []
                        current.append(line.strip())
                    if current:
                        out.append((title, " ".join(current)))
                elif para.strip():
                    out.append((title, " ".join(l.strip() for l in lines)))
        return out


def has(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.I) is not None


def has_value(text: str, value) -> bool:
    return value is not None and any(matches(n, value) for n in find_numbers(text))


def blocks_with(report: Report, pattern: str, exclude_methodology: bool = True) -> list[tuple[str, str]]:
    return [(t, b) for t, b in report.blocks(exclude_methodology) if has(pattern, b)]


def section_has(report: Report, title: str, pattern: str) -> bool:
    return has(pattern, report.sections.get(title, ""))


# --- expected values from the data ------------------------------------------------------------------

@dataclass
class Truth:
    year: int
    total_pct: float
    changes: dict[str, float]
    phishing_peak: str            # month name
    malware: dict[str, dict]
    previous_top_family: str | None
    countries: dict[str, dict]
    sectors: dict[str, dict]
    unmapped: list[str]

    @classmethod
    def compute(cls, year: int) -> "Truth":
        changes = {r["attack_type"]: r["pct_change"] for r in rt.attack_type_changes(year)["value"]["rows"]}
        peak = rt.monthly_series(year, attack_type="phishing")["value"]["peak_month"]
        malware = {r["family"]: r for r in rt.top_malware(year, n=1000)["value"]["rows"]}
        prev_top = next((f for f, r in malware.items() if r["previous_rank"] == 1), None)
        return cls(
            year=year,
            total_pct=rt.compare_years(year)["value"]["pct_change"],
            changes=changes,
            phishing_peak=MONTH_NAMES[int(peak[5:7]) - 1] if peak else "",
            malware=malware,
            previous_top_family=prev_top,
            countries={r["country"]: r for r in rt.top_countries(year, n=1000)["value"]["rows"]},
            sectors={r["sector"]: r for r in rt.sector_breakdown(year)["value"]["rows"]},
            unmapped=[r["vendor_name"] for r in rt.unmapped_malware(year)["value"]["rows"]],
        )


# --- LLM judge --------------------------------------------------------------------------------------

class Judge:
    """Yes/no questions about report excerpts, answered by a local model."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.calls: list[dict] = []
        self._llm = None

    def ask(self, question: str, excerpt: str) -> bool | None:
        if not self.enabled or not excerpt.strip():
            return None
        from langchain_core.messages import HumanMessage, SystemMessage
        from pydantic import BaseModel

        from agents.structured import complete

        class Verdict(BaseModel):
            answer: bool
            reason: str = ""

        if self._llm is None:
            from agents.llm import get_llm
            judge_model = os.environ.get("EVAL_JUDGE_MODEL", "").strip()
            if judge_model:
                os.environ["LLM_MODEL"] = judge_model
            self._llm = get_llm(reasoning_effort="low").bind(response_format={"type": "json_object"})
        system = (Path(__file__).parent / "judge_prompt.md").read_text(encoding="utf-8")
        messages = [SystemMessage(system), HumanMessage(f"Question: {question}\n\nReport excerpt:\n{excerpt}")]
        verdict = complete(self._llm, messages, Verdict)
        self.calls.append({"question": question, "answer": verdict.answer, "reason": verdict.reason})
        return verdict.answer


# --- patterns ---------------------------------------------------------------------------------------

@dataclass
class Result:
    number: int
    title: str
    found: bool = False
    correct: bool = False
    caveat: bool | None = None     # None: no caveat applies
    notes: list[str] = field(default_factory=list)

    @property
    def points(self) -> int:
        return int(self.found) + int(self.correct) + int(bool(self.caveat))

    @property
    def max_points(self) -> int:
        return 2 if self.caveat is None else 3


def _excerpt(blocks) -> str:
    return "\n\n".join(f"[{t}] {b}" for t, b in blocks)


def p1_total_vs_types(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(1, "Total blocked fell while most types rose; brute force drove the drop", caveat=False)
    total = [(t, b) for t, b in report.blocks(True) if has_value(b, truth.total_pct)
             and has(r"\b(total|overall|all products|combined|in all|across)\b", b)]
    brute = [(t, b) for t, b in blocks_with(report, r"brute[- ]?force") if has_value(b, truth.changes["brute_force"])]
    r.found = bool(total or brute)
    total_down = any(has(DOWN, b) for _, b in total)
    brute_down = any(has(DOWN, b) for _, b in brute)
    r.notes += [f"total decline stated: {total_down}", f"brute force decline stated: {brute_down}"]
    if r.found:
        verdict = judge.ask(
            "Does the report explain that the overall number of blocked attacks fell mainly because of a "
            "drop in brute-force attempts, while most other attack types rose (rather than only saying "
            "that attacks went down)?", _excerpt(total + brute + blocks_with(report, r"\b(most|other) attack")))
        r.notes.append(f"judge: {verdict}")
        r.correct = total_down and brute_down and (verdict if verdict is not None else True)
        r.caveat = any(section_has(report, t, OVERCOUNT) for t, _ in total) if total else False
    return r


def p2_phishing(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(2, "Phishing up sharply, with a spike in one month")
    blocks = blocks_with(report, r"phishing")
    with_value = [b for _, b in blocks if has_value(b, truth.changes["phishing"])]
    r.found = bool(with_value)
    rose = any(has(UP, b) for b in with_value)
    month = truth.phishing_peak
    spike = any(has(rf"\b{month}\b", b) or has(rf"{truth.year}-{MONTH_NAMES.index(month) + 1:02d}", b)
                for _, b in blocks) if month else False
    r.notes += [f"rise stated: {rose}", f"{month} spike mentioned: {spike}"]
    r.correct = r.found and rose and spike
    return r


def p3_lumma(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(3, "LummaStealer new in 2026 and the #1 family", caveat=False)
    blocks = blocks_with(report, r"lumma")
    r.found = bool(blocks)
    is_new = any(has(NEW, b) for _, b in blocks)
    is_top = any(has(TOP, b) for _, b in blocks)
    ahead = bool(truth.previous_top_family) and any(has(truth.previous_top_family, b) for _, b in blocks)
    r.notes += [f"new: {is_new}", f"#1: {is_top}", f"compared with {truth.previous_top_family}: {ahead}"]
    r.correct = r.found and is_new and is_top
    r.caveat = any(section_has(report, t, UNMAPPED) for t, _ in blocks)
    return r


def p4_akira(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(4, "Akira new and ahead of LockBit; ransomware fell overall")
    blocks = blocks_with(report, r"akira")
    r.found = bool(blocks)
    is_new = any(has(NEW, b) for _, b in blocks)
    vs_lockbit = any(has(r"lockbit", b) for _, b in blocks)
    ransomware_down = any(has_value(b, truth.changes["ransomware"]) and has(DOWN, b)
                          for _, b in blocks_with(report, r"ransomware"))
    r.notes += [f"new: {is_new}", f"compared with LockBit: {vs_lockbit}", f"ransomware decline stated: {ransomware_down}"]
    r.correct = r.found and is_new and vs_lockbit and ransomware_down
    return r


def p5_credential_theft(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(5, "Credential theft up sharply, consistent with the new info stealer")
    blocks = [(t, b) for t, b in blocks_with(report, r"credential") if has_value(b, truth.changes["credential_theft"])]
    r.found = bool(blocks)
    rose = any(has(UP, b) for _, b in blocks)
    keyword_link = any(has(r"(lumma|stealer)", b) for _, b in blocks)
    verdict = None
    if r.found and not keyword_link:
        verdict = judge.ask("Does the report connect the rise in credential theft to the rise of an "
                            "information-stealing malware family?",
                            _excerpt(blocks + blocks_with(report, r"(lumma|stealer)")))
    linked = keyword_link or bool(verdict)
    r.notes += [f"rise stated: {rose}", f"linked to the info stealer: {linked}"
                + ("" if verdict is None else f" (judge: {verdict})")]
    r.correct = r.found and rose and linked
    return r


def p6_brazil(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(6, "Brazil rose from #10 to #3 among source countries", caveat=False)
    br = truth.countries.get("BR", {})
    blocks = blocks_with(report, r"(brazil|\bBR\b)")
    r.found = bool(blocks)
    rank = any(has_value(b, br.get("rank")) or has(r"\bthird\b|#\s*3\b", b) for _, b in blocks)
    prev = any(has_value(b, br.get("previous_rank")) or has(r"\btenth\b", b) or has(UP, b) for _, b in blocks)
    r.notes += [f"rank {br.get('rank')} stated: {rank}", f"rise from rank {br.get('previous_rank')} stated: {prev}"]
    r.correct = r.found and rank and prev
    r.caveat = any(section_has(report, t, GEOLOCATION) for t, _ in blocks)
    return r


def p7_energy(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(7, "Energy is the most targeted sector, with a growing share", caveat=False)
    energy = truth.sectors.get("Energy", {})
    blocks = blocks_with(report, r"\benergy\b")
    r.found = bool(blocks)
    top = any(has(TOP, b) or has(r"primary target|most of the attacks", b) for _, b in blocks)
    share = any(has_value(b, energy.get("share_pct")) for _, b in blocks)
    r.notes += [f"most targeted: {top}", f"share {energy.get('share_pct')}% stated: {share}"]
    r.correct = r.found and top and share
    r.caveat = any(section_has(report, t, OVERCOUNT) for t, _ in blocks)
    return r


def p8_kryptik(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(8, "Data gap: Win32/Kryptik.gen flagged as unmapped")
    blocks = blocks_with(report, r"kryptik", exclude_methodology=False)
    r.found = bool(blocks)
    flagged = any(has(UNMAPPED, b) for _, b in blocks)
    in_body = bool(blocks_with(report, r"kryptik"))
    r.notes += [f"flagged as unmapped: {flagged}", f"mentioned outside the methodology: {in_body}"]
    r.correct = r.found and flagged
    return r


def p9_overcount(report: Report, truth: Truth, judge: Judge, run_dir: Path) -> Result:
    """Every section that quotes a cross-product finding should state the overcount caveat."""
    r = Result(9, "Trap: summing across products overstates attacks")
    findings = {}
    path = run_dir / "normalized.json"
    if path.is_file():
        findings = {f["id"]: f for f in json.loads(path.read_text(encoding="utf-8"))}
    cross = {fid for fid, f in findings.items() if any("Summed across products" in c for c in f.get("caveats", []))}
    needing = [t for t, body in report.sections.items()
               if not t.lower().startswith("methodology") and any(f"[{fid}" in body or f", {fid}" in body for fid in cross)]
    missing = [t for t in needing if not section_has(report, t, OVERCOUNT)]
    # The answer key accepts either: say that summed figures overcount, or report per product.
    per_product_only = not needing
    r.found = has(OVERCOUNT, report.text) or per_product_only
    r.notes += [f"sections quoting summed figures: {len(needing)}",
                f"of those without the caveat: {', '.join(missing) or 'none'}",
                f"reports per product only: {per_product_only}"]
    r.correct = r.found and not missing
    return r


def p10_ingestion(report: Report, truth: Truth, judge: Judge) -> Result:
    r = Result(10, "Ingestion rejects the broken delivery as a whole")
    path = ROOT / "data" / "exports_bad" / "edr_2026_resubmission.csv"
    products = {p["product"] for p in rt.list_products()["value"]}
    v = ingest.validate(path.read_bytes(), products)
    kinds = {k: any(f"invalid {k}" in e for e in v.errors) for k in ("month", "action", "source_country", "count")}
    r.found = bool(v.errors)
    r.correct = all(kinds.values())
    r.notes.append("errors found: " + ", ".join(f"{k}={ok}" for k, ok in kinds.items()))
    return r


PATTERNS = [p1_total_vs_types, p2_phishing, p3_lumma, p4_akira, p5_credential_theft, p6_brazil,
            p7_energy, p8_kryptik, p9_overcount, p10_ingestion]


def score_run(run_dir: Path, use_llm: bool = True, year: int | None = None) -> dict:
    run_dir = Path(run_dir)
    report = Report.load(run_dir)
    if year is None:
        m = re.search(r"^# .*?(20\d\d)", report.text, re.M)
        year = int(m.group(1)) if m else 2026
    truth = Truth.compute(year)
    judge = Judge(use_llm)
    results = []
    for check in PATTERNS:
        if check is p9_overcount:
            results.append(check(report, truth, judge, run_dir))
        else:
            results.append(check(report, truth, judge))
    points = sum(r.points for r in results)
    maximum = sum(r.max_points for r in results)
    return {"run": str(run_dir), "year": year, "points": points, "max_points": maximum,
            "score_pct": round(100 * points / maximum, 1) if maximum else 0.0,
            "patterns": [{"number": r.number, "title": r.title, "found": r.found, "correct": r.correct,
                          "caveat": r.caveat, "points": r.points, "max_points": r.max_points, "notes": r.notes}
                         for r in results],
            "judge": judge.calls, "llm_judge": use_llm}


def print_score(score: dict, out=None) -> None:
    out = out or sys.stdout
    def mark(v):
        return "n/a" if v is None else ("yes" if v else "no")
    print(f"Run: {score['run']}  (year {score['year']}, LLM judge {'on' if score['llm_judge'] else 'off'})", file=out)
    print(f"{'#':>2}  {'pattern':<68} {'found':>5} {'right':>5} {'caveat':>6} {'pts':>5}", file=out)
    for p in score["patterns"]:
        print(f"{p['number']:>2}  {p['title'][:68]:<68} {mark(p['found']):>5} {mark(p['correct']):>5} "
              f"{mark(p['caveat']):>6} {p['points']:>2}/{p['max_points']}", file=out)
        for note in p["notes"]:
            print(f"      {note}", file=out)
    print(f"\nTotal: {score['points']}/{score['max_points']} ({score['score_pct']}%)", file=out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Score a run's report against eval/answer_key.md.")
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--no-llm", action="store_true", help="keyword and value checks only")
    parser.add_argument("--json", action="store_true", help="also write score.json to the run folder")
    args = parser.parse_args(argv)
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env", override=False)
    try:
        score = score_run(args.run_dir, use_llm=not args.no_llm)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        return 1
    print_score(score)
    if args.json:
        (args.run_dir / "score.json").write_text(json.dumps(score, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
