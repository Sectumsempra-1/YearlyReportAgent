"""Normalizer (SPEC 7.2).

STUB: the ATT&CK mappings are fixed fake data instead of model output, and
technique IDs are not yet checked against the MITRE dataset (later step).

The confidence threshold is real code: mappings below MIN_CONFIDENCE are left
out of the findings and listed in review.json.
"""

from agents.runs import save
from agents.state import NormalizedFinding, TechniqueMapping

MIN_CONFIDENCE = 0.6


def apply_confidence_threshold(findings: list[NormalizedFinding]) -> tuple[list[NormalizedFinding], list[dict]]:
    kept, review = [], []
    for f in findings:
        low = [m for m in f.attack_techniques if m.confidence < MIN_CONFIDENCE]
        review += [{"finding_id": f.id, "technique_id": m.technique_id, "confidence": m.confidence}
                   for m in low]
        kept.append(f.model_copy(update={
            "attack_techniques": [m for m in f.attack_techniques if m.confidence >= MIN_CONFIDENCE]}))
    return kept, review


def normalizer(state: dict) -> dict:
    stub = []
    for i, f in enumerate(state["findings"]):
        mappings = [TechniqueMapping(technique_id="T1190", confidence=0.9)]
        if i == 0:
            mappings.append(TechniqueMapping(technique_id="T1566", confidence=0.5))  # low: goes to review
        stub.append(NormalizedFinding(**f.model_dump(), attack_techniques=mappings, confidence=0.8))
    normalized, review = apply_confidence_threshold(stub)
    save(state["run_dir"], "normalized.json", normalized)
    save(state["run_dir"], "review.json", review)
    return {"normalized": normalized}
