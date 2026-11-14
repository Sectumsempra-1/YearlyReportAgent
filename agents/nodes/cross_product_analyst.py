"""Cross-product analyst (SPEC 7.1a): owns all calls with product=None.

STUB: returns fixed fake findings instead of calling the model.

Input (sent by the graph): {"year", "run_dir"}.
Output: {"drafts": [FindingDraft, ...]} with product "ALL".
"""

from agents.runs import save
from agents.state import FindingDraft, Source


def cross_product_analyst(payload: dict) -> dict:
    year = payload["year"]
    drafts = [
        FindingDraft(
            product="ALL",
            statement="STUB: the top source country accounts for a share of attack volume.",
            values={"share_pct": 20.0},
            source=Source(function="top_countries", params={"year": year, "n": 10, "product": None},
                          key_paths={"share_pct": "value.rows.0.share_pct"}),
        ),
        FindingDraft(
            product="ALL",
            statement="STUB: some malware names have no family mapping.",
            values={"detections": 100},
            source=Source(function="unmapped_malware", params={"year": year, "product": None},
                          key_paths={"detections": "value.rows.0.detections"}),
            data_gap=True,
        ),
    ]
    save(payload["run_dir"], "analyst_cross_product.json", drafts)
    return {"drafts": drafts}
