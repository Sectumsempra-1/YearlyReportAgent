"""Product analyst (SPEC 7.1): one per product, in parallel.

STUB: returns fixed fake findings instead of calling the model. Replaced by
the real agent in a later step.

Input (sent by the graph): {"year", "run_dir", "product"}.
Output: {"drafts": [FindingDraft, ...]}.
"""

from agents.runs import save, slug
from agents.state import FindingDraft, Source


def analyst(payload: dict) -> dict:
    year, product = payload["year"], payload["product"]
    drafts = [
        FindingDraft(
            product=product,
            statement=f"STUB: {product} blocked attacks in {year}.",
            values={"blocked": 1000},
            source=Source(function="attacks_blocked",
                          params={"year": year, "product": product, "attack_type": None},
                          key_paths={"blocked": "value"}),
        ),
        FindingDraft(
            product=product,
            statement=f"STUB: {product} blocked attacks changed compared with {year - 1}.",
            values={"pct_change": 12.5},
            source=Source(function="compare_years",
                          params={"year": year, "product": product, "attack_type": None},
                          key_paths={"pct_change": "value.pct_change"}),
        ),
    ]
    save(payload["run_dir"], f"analyst_{slug(product)}.json", drafts)
    return {"drafts": drafts}
