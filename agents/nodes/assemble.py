"""Final assembly (SPEC 7.7). Code, no model.

Writes report.md (with finding tags) and report_clean.md (tags removed) in
section order. The methodology section is generated here from the data
sources, the caveats and the data gaps.
"""

import re

from agents.runs import save, save_text
from agents.state import METHODOLOGY_ID, REPORT_ORDER, SECTION_TITLES, Section

TAG_RE = re.compile(r"\s*\[F-\d{3,}(?:,\s*F-\d{3,})*\]")


def remove_tags(markdown: str) -> str:
    return TAG_RE.sub("", markdown)


def build_methodology(findings: list) -> Section:
    functions = sorted({f.source.function for f in findings})
    caveats = list(dict.fromkeys(c for f in findings for c in f.caveats))
    gaps = [f for f in findings if f.data_gap]
    lines = ["**Data sources.** Monthly aggregated counts delivered by each product team, "
             "loaded and validated by ingest.py, and queried read-only through: "
             + ", ".join(f"`{name}`" for name in functions) + "."]
    if caveats:
        lines += ["", "**Caveats.**", ""] + [f"- {c}" for c in caveats]
    lines += ["", "**Data gaps.**", ""]
    lines += [f"- {f.statement} [{f.id}]" for f in gaps] or ["- None reported."]
    return Section(id=METHODOLOGY_ID, title=SECTION_TITLES[METHODOLOGY_ID], markdown="\n".join(lines),
                   finding_ids_used=[f.id for f in gaps])


def assemble(state: dict) -> dict:
    methodology = build_methodology(state.get("normalized", []))
    sections = {**state["sections"], METHODOLOGY_ID: methodology}
    parts = [f"# Yearly security report {state['year']}"]
    parts += [f"## {sections[sid].title}\n\n{sections[sid].markdown}" for sid in REPORT_ORDER]
    report = "\n\n".join(parts) + "\n"
    save(state["run_dir"], "section_methodology.json", methodology)
    save_text(state["run_dir"], "report.md", report)
    save_text(state["run_dir"], "report_clean.md", remove_tags(report))
    return {"sections": {METHODOLOGY_ID: methodology}, "status": "completed"}
