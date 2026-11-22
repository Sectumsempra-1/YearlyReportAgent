"""Cross-product analyst (SPEC 7.1a): owns all calls with product=None.

Same agent as the product analyst (agents/nodes/analyst.py): it explores with
the report_tools tools and answers with findings as JSON; code checks every
finding against its cited tool call. Its scope is all products together: a
finding that cites a call for one product is dropped (finding_check).
Its findings have product "ALL".

Input (sent by the graph): {"year", "run_dir"}.
Output: {"drafts": [FindingDraft, ...]}.

Saved to the run folder: analyst_cross_product.json, _dropped.json and
_transcript.json, like the product analysts.
"""

from agents.nodes.analyst import run_analyst


def make_cross_product_analyst(llm=None):
    """Build the node. Without an llm, the client comes from agents.llm at run time."""

    def cross_product_analyst(payload: dict) -> dict:
        from agents.llm import get_llm
        model = llm or get_llm()
        kept = run_analyst(model, payload["year"], None, "cross_product_analyst", payload["run_dir"],
                           "analyst_cross_product")
        return {"drafts": kept}

    return cross_product_analyst


cross_product_analyst = make_cross_product_analyst()
