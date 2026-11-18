"""Normalizer (SPEC 7.2). No tools.

The model maps each finding to MITRE ATT&CK techniques, chosen from the list
of active techniques in the pinned dataset (added to the prompt by code), sets sector and
severity, links related findings and gives confidence scores. Code then
checks everything the model said:

- technique IDs must exist in the pinned ATT&CK dataset and be neither
  revoked nor deprecated; others are rejected. Valid ones get their name.
- technique mappings below MIN_CONFIDENCE are left out and listed in
  review.json; findings whose overall confidence is below it are kept and
  also listed in review.json
- sector and severity must be standard values that appear in the data the
  finding cites (the objects around its key paths in the re-run tool
  result); otherwise they are reset to "unspecified"
- related findings must be other existing finding IDs
- every finding gets a normalization; a finding the model skipped gets
  none (confidence 0) and goes to review

Findings are sent in batches of BATCH_SIZE, each with a short list of all
findings so related findings can be linked across batches.

Saved to the run folder: normalizer_output_<n>.json (the model's answer per batch),
normalized.json, review.json, normalizer_corrections.json (everything code
rejected or reset, and why).
"""

import json
import logging

from langchain_core.messages import HumanMessage, SystemMessage

from agents.attack import ATTACK_VERSION, BUNDLE_PATH, check_technique, load_techniques
from agents.finding_check import FUNCTIONS, resolve
from agents.prompt_loader import load_prompt
from agents.runs import save
from agents.state import (
    FindingNormalization, NormalizedFinding, NormalizerOutput, TechniqueMapping,
)
from agents.structured import complete
from ingest import SECTORS, SEVERITIES

log = logging.getLogger(__name__)

MIN_CONFIDENCE = 0.6
BATCH_SIZE = 3  # findings per model request; one request for many findings outruns any timeout

# Measured on qwen3.5:9b with the technique list in the prompt: "none" answered
# 9 findings in under a minute with good picks; with "low" every batch ran out
# of tokens while reasoning. The list does the work that reasoning did.
REASONING_EFFORT = "none"


def technique_list(path=BUNDLE_PATH) -> str:
    """Active parent techniques from the pinned dataset, one 'ID Name' per line, for the prompt."""
    active = [t for t in load_techniques(path).values()
              if not t.revoked and not t.deprecated and "." not in t.id]
    return "\n".join(f"{t.id} {t.name}" for t in sorted(active, key=lambda t: t.id))
FREE_SECTOR = {"multiple", "unspecified"}
FREE_SEVERITY = {"unspecified"}


# --- checks (code) -------------------------------------------------------------------------------

def apply_confidence_threshold(findings: list[NormalizedFinding]) -> tuple[list[NormalizedFinding], list[dict]]:
    """Leave out technique mappings below MIN_CONFIDENCE; list them, and low-confidence findings, for review."""
    kept, review = [], []
    for f in findings:
        low = [m for m in f.attack_techniques if m.confidence < MIN_CONFIDENCE]
        review += [{"finding_id": f.id, "kind": "technique", "technique_id": m.technique_id,
                    "name": m.name, "confidence": m.confidence, "rationale": m.rationale} for m in low]
        if f.confidence < MIN_CONFIDENCE:
            review.append({"finding_id": f.id, "kind": "finding", "confidence": f.confidence,
                           "statement": f.statement})
        kept.append(f.model_copy(update={
            "attack_techniques": [m for m in f.attack_techniques if m.confidence >= MIN_CONFIDENCE]}))
    return kept, review


def labels_in_cited_data(finding) -> set[str]:
    """Strings shown in the data a finding cites: string values, and keys with a non-zero count,
    inside the objects that hold its cited values (e.g. the ranked row, or the attack type's entry)."""
    try:
        result = FUNCTIONS[finding.source.function](**finding.source.params)
    except Exception:
        return set()
    labels: set[str] = {v for v in finding.values.values() if isinstance(v, str)}
    labels |= {v for v in finding.source.params.values() if isinstance(v, str)}

    def walk(node):
        if isinstance(node, str):
            labels.add(node)
        elif isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, (int, float)) and not isinstance(value, bool):
                    if value:
                        labels.add(key)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    for path in finding.source.key_paths.values():
        parent = path.rsplit(".", 1)[0] if "." in path else path
        try:
            walk(resolve(result, parent))
        except (KeyError, IndexError, ValueError, TypeError):
            continue
    return labels


def check_label(raw: str, standard: set[str], free: set[str], shown: set[str]) -> tuple[str, str]:
    """Return (value, problem). Standardizes case; resets to 'unspecified' with a reason."""
    value = raw.strip()
    if value.lower() in free:
        return value.lower(), ""
    canonical = {s.lower(): s for s in standard}.get(value.lower())
    if canonical is None:
        return "unspecified", f"{raw!r} is not a standard value"
    if canonical not in shown:
        return "unspecified", f"{canonical!r} does not appear in the data the finding cites"
    return canonical, ""


def check_normalization(finding, norm: FindingNormalization | None, finding_ids: set[str],
                        bundle_path=BUNDLE_PATH) -> tuple[NormalizedFinding, list[dict]]:
    """Apply the code checks to the model's answer for one finding."""
    corrections: list[dict] = []

    def note(kind, value, reason):
        corrections.append({"finding_id": finding.id, "kind": kind, "value": value, "reason": reason})

    if norm is None:
        note("normalization", None, "the model returned no normalization for this finding")
        return NormalizedFinding(**finding.model_dump(), confidence=0.0), corrections

    techniques, seen = [], set()
    for t in norm.attack_techniques:
        name, reason = check_technique(t.technique_id, bundle_path)
        if name is None:
            note("technique", t.technique_id, reason)
            continue
        tid = t.technique_id.strip().upper()
        if tid in seen:
            continue
        seen.add(tid)
        techniques.append(TechniqueMapping(technique_id=tid, name=name, confidence=t.confidence,
                                           rationale=t.rationale))

    shown = labels_in_cited_data(finding)
    sector, problem = check_label(norm.sector, SECTORS, FREE_SECTOR, shown)
    if problem:
        note("sector", norm.sector, problem)
    severity, problem = check_label(norm.severity, SEVERITIES, FREE_SEVERITY, shown)
    if problem:
        note("severity", norm.severity, problem)

    related = []
    for rid in norm.related_findings:
        if rid == finding.id or rid not in finding_ids:
            note("related_finding", rid, "the finding itself" if rid == finding.id else "no such finding")
        elif rid not in related:
            related.append(rid)

    return NormalizedFinding(**finding.model_dump(), attack_techniques=techniques, sector=sector,
                             severity=severity, related_findings=related,
                             confidence=norm.confidence), corrections


def finding_for_model(f) -> dict:
    """What the model sees of a finding."""
    return {"id": f.id, "product": f.product, "statement": f.statement, "values": f.values,
            "source": {"function": f.source.function, "params": f.source.params},
            "direction": f.direction, "caveats": f.caveats, "data_gap": f.data_gap}


# --- node ------------------------------------------------------------------------------------------

def batch_message(batch: list, all_findings: list) -> str:
    """The user message for one batch: every finding in short (for linking), then the batch in full."""
    overview = [{"id": f.id, "product": f.product, "statement": f.statement} for f in all_findings]
    compact = {"ensure_ascii": False, "separators": (",", ":")}
    return ("All findings in this report, for related_findings:\n" + json.dumps(overview, **compact)
            + "\n\nNormalize only these findings, one entry each:\n"
            + json.dumps([finding_for_model(f) for f in batch], **compact))


def make_normalizer(llm=None, bundle_path=None, batch_size: int = BATCH_SIZE):
    """Build the normalizer node. Without an llm, the client comes from agents.llm at run time."""

    def normalizer(state: dict) -> dict:
        path = bundle_path or BUNDLE_PATH
        run_dir, findings = state["run_dir"], state["findings"]
        load_techniques(path)  # fail early with a clear message if the dataset is missing
        if not findings:
            for name, data in (("normalized.json", []), ("review.json", []),
                               ("normalizer_corrections.json", [])):
                save(run_dir, name, data)
            return {"normalized": []}

        from agents.llm import get_llm
        model = llm or get_llm(reasoning_effort=REASONING_EFFORT)
        system = load_prompt("normalizer", attack_version=ATTACK_VERSION,
                             techniques=technique_list(path))
        ids = {f.id for f in findings}
        by_id: dict[str, FindingNormalization] = {}
        corrections: list[dict] = []

        batches = [findings[i:i + batch_size] for i in range(0, len(findings), batch_size)]
        for n, batch in enumerate(batches, 1):
            log.info("normalizer: batch %d of %d", n, len(batches))
            messages = [SystemMessage(system), HumanMessage(batch_message(batch, findings))]
            output = complete(model, messages, NormalizerOutput)
            save(run_dir, f"normalizer_output_{n}.json", output)
            batch_ids = {f.id for f in batch}
            for norm in output.findings:
                if norm.finding_id not in ids:
                    reason = "no such finding; ignored"
                elif norm.finding_id not in batch_ids:
                    reason = "not in this batch; ignored"
                elif norm.finding_id in by_id:
                    reason = "duplicate entry; the first one is used"
                else:
                    by_id[norm.finding_id] = norm
                    continue
                corrections.append({"finding_id": norm.finding_id, "kind": "normalization",
                                    "value": None, "reason": reason})

        normalized = []
        for f in findings:
            nf, c = check_normalization(f, by_id.get(f.id), ids, path)
            normalized.append(nf)
            corrections += c
        normalized, review = apply_confidence_threshold(normalized)
        for c in corrections:
            log.warning("normalizer: %s %s %r: %s", c["finding_id"], c["kind"], c["value"], c["reason"])

        save(run_dir, "normalized.json", normalized)
        save(run_dir, "review.json", review)
        save(run_dir, "normalizer_corrections.json", corrections)
        return {"normalized": normalized}

    return normalizer


normalizer = make_normalizer()
