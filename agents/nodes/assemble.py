"""Final assembly (SPEC 7.7). Code, no model.

Builds the methodology section from the data sources, the caveats and the
data gaps, checks it with verify.py (its numbers are tagged like any other
section's), then writes report.md (with finding tags) and report_clean.md
(tags removed) in section order.

If the methodology fails verification, no report is written: the run ends
with status "failed" and failures.json, like a section that failed its
attempts.
"""

import re

import report_tools
from agents.attack import ATTACK_VERSION
from agents.runs import save, save_text
from agents.state import METHODOLOGY_ID, REPORT_ORDER, SECTION_TITLES, Section
from text_numbers import find_numbers, matches
from verify import verify_section

TAG_RE = re.compile(r"\s*\[F-\d{3,}(?:,\s*F-\d{3,})*\]")


def remove_tags(markdown: str) -> str:
    return TAG_RE.sub("", markdown)


def tag_numbers(text: str, finding) -> str:
    """Put the finding's tag after every number in `text` that is one of its values."""
    values = [*finding.values.values(), *finding.source.params.values()]
    out, last = [], 0
    for number in find_numbers(text):
        if any(matches(number, v) for v in values):
            out += [text[last:number.end], f" [{finding.id}]"]
            last = number.end
    return "".join(out) + text[last:]


def _join(items: list[str]) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def build_methodology(state: dict) -> Section:
    """Data sources, caveats, ATT&CK mapping and data gaps, from the findings and the data."""
    findings = state.get("normalized", [])
    sections = state.get("sections", {})
    used_ids = {fid for sid in REPORT_ORDER if sid in sections for fid in sections[sid].finding_ids_used}
    used = [f for f in findings if f.id in used_ids]
    year = state["year"]

    products = report_tools.list_products()["value"]
    source_lines = [f"- {p['product']} ({p['category']}): "
                    + (_join([str(y) for y in p["years_loaded"]]) if p["years_loaded"] else "no data loaded")
                    for p in products]
    functions = sorted({f.source.function for f in used})
    lines = [
        f"This report covers {year} compared with {year - 1}. It is based on monthly aggregated counts "
        "delivered by each product team, with no client names. Each delivery was validated before "
        "loading; a file with any invalid row was rejected as a whole.",
        "",
        "**Data sources** (product, and the years loaded):",
        "",
        *source_lines,
        "",
        "Every figure in this report comes from a read-only query of that data"
        + (f" ({', '.join(f'`{name}`' for name in functions)})" if functions else "")
        + " and is checked against the query before the report is published. "
        "Each figure is traceable to its finding.",
    ]

    caveats = list(dict.fromkeys(c for f in used for c in f.caveats))
    lines += ["", "**Caveats.**", ""] + ([f"- {c}" for c in caveats] or ["- None."])

    techniques = sorted({(m.technique_id, m.name) for f in used for m in f.attack_techniques})
    lines += ["", "**MITRE ATT&CK.** Findings were mapped to techniques from MITRE ATT&CK for "
              f"Enterprise v{ATTACK_VERSION}. Mappings with low confidence were left out of this report "
              "and listed for human review."]
    if techniques:
        lines += ["", "Techniques referenced:", ""] + [f"- {tid} {name}" for tid, name in techniques]

    gaps = [f for f in findings if f.data_gap]
    lines += ["", "**Data gaps.** Missing or unmapped data is reported here, never estimated.", ""]
    lines += [f"- {tag_numbers(f.statement, f)} [{f.id}]" for f in gaps] or ["- None reported."]

    markdown = "\n".join(lines)
    return Section(id=METHODOLOGY_ID, title=SECTION_TITLES[METHODOLOGY_ID], markdown=markdown,
                   finding_ids_used=list(dict.fromkeys(f.id for f in gaps)))


def assemble(state: dict) -> dict:
    run_dir = state["run_dir"]
    methodology = build_methodology(state)
    save(run_dir, "section_methodology.json", methodology)

    gap_findings = {f.id: f for f in state.get("normalized", []) if f.id in methodology.finding_ids_used}
    check = verify_section(methodology, gap_findings)
    save(run_dir, "verify_methodology.json", check)
    if not check.passed:
        save(run_dir, "failures.json", {METHODOLOGY_ID: {"attempts": 1, "errors": check.errors}})
        return {"failed": {METHODOLOGY_ID: check.errors}, "status": "failed"}

    sections = {**state["sections"], METHODOLOGY_ID: methodology}
    missing = [sid for sid in REPORT_ORDER if sid not in sections]
    if missing:
        raise ValueError(f"cannot assemble the report; missing sections: {missing}")
    year = state["year"]
    parts = [f"# Yearly security report {year}", "", f"Compared with {year - 1}."]
    parts += [f"\n## {sections[sid].title}\n\n{sections[sid].markdown}" for sid in REPORT_ORDER]
    report = "\n".join(parts) + "\n"
    save_text(run_dir, "report.md", report)
    save_text(run_dir, "report_clean.md", remove_tags(report))
    return {"sections": {METHODOLOGY_ID: methodology}, "status": "completed"}
