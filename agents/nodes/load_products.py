"""Read the product list from report_tools (code, no model)."""

import report_tools
from agents.runs import save


def load_products(state: dict) -> dict:
    result = report_tools.list_products()
    save(state["run_dir"], "products.json", result)
    return {"products": [p["product"] for p in result["value"]], "status": "running"}
