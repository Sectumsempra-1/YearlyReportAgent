"""Code check for analyst findings (SPEC 7.1). No model.

Re-runs the tool call a finding cites and checks that every value in the
finding is exactly the value at its key path in that result. Also enforces
the analyst's scope: a product analyst may only cite calls for its own
product, the cross-product analyst only calls with product=None
(list_products() is allowed for both).
"""

import report_tools

FUNCTIONS = {f.__name__: f for f in report_tools.TOOLS}
UNSCOPED = {"list_products"}


def resolve(result, path: str):
    """Follow a dotted key path ('value.rows.0.share_pct') into a tool result."""
    node = result
    if not path:
        return node
    for part in path.split("."):
        if isinstance(node, list):
            node = node[int(part)]
        elif isinstance(node, dict):
            node = node[part]
        else:
            raise KeyError(part)
    return node


def same_value(expected, actual) -> bool:
    """Exact match. 12 and 12.0 are equal; True and 1 are not."""
    if isinstance(expected, bool) or isinstance(actual, bool):
        return isinstance(expected, bool) and isinstance(actual, bool) and expected == actual
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return expected == actual
    return type(expected) is type(actual) and expected == actual


def check_finding(finding, scope_product: str | None) -> list[str]:
    """Return the problems with a finding; an empty list means it passes.

    scope_product is the analyst's product, or None for the cross-product analyst.
    """
    source = finding.source
    params = source.params
    if source.function not in UNSCOPED:
        cited = params.get("product")
        if cited != scope_product:
            expected = "product=None" if scope_product is None else f"product={scope_product!r}"
            return [f"{source.function} was called with product={cited!r}; this analyst may only "
                    f"cite calls with {expected}"]
    try:
        result = FUNCTIONS[source.function](**params)
    except Exception as exc:
        return [f"cited call {source.function}({params}) failed: {type(exc).__name__}: {exc}"]

    problems = []
    for name, path in source.key_paths.items():
        if path != "value" and not path.startswith("value."):
            problems.append(f"{name}: key path {path!r} must start with 'value'")
            continue
        try:
            actual = resolve(result, path)
        except (KeyError, IndexError, ValueError, TypeError):
            problems.append(f"{name}: key path {path!r} not found in the {source.function} result")
            continue
        if not same_value(finding.values[name], actual):
            problems.append(f"{name}: finding says {finding.values[name]!r} but {path} is {actual!r}")
    return problems
