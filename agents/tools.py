"""report_tools functions wrapped as LangGraph tools.

One tool per function in `report_tools.TOOLS`, with the same name. The tool
description is the function's docstring. The argument schema is built from
the function signature, with a description for every parameter, so the model
sees typed, documented arguments (attack types are an enum, n must be >= 1).

Each tool returns the full result dict, {"value", "source", "caveats"}, so
findings can cite the source and keep the caveats (rules 1 and 6). LangGraph's
ToolNode serializes it to JSON for the model.

Invalid arguments (unknown product, wrong type, value out of range) come back
to the model as an error message it can correct, instead of crashing the run.
A missing database is a setup problem, not the model's, so it is raised.
"""

import inspect
from typing import Literal, Optional

from langchain_core.tools import StructuredTool, ToolException
from pydantic import Field, create_model

import report_tools
from ingest import ATTACK_TYPES

AttackType = Literal[tuple(sorted(ATTACK_TYPES))]  # type: ignore[valid-type]

# Descriptions are general: they explain the parameter, never the data (rule 8).
PARAM_DESCRIPTIONS = {
    "year": "Report year. The previous year (year - 1) is used for comparisons.",
    "product": "Product name exactly as returned by list_products().",
    "product_optional": (
        "Product name exactly as returned by list_products(). "
        "Leave out (null) to combine all products."
    ),
    "attack_type": "Limit to one attack type. Leave out (null) for all attack types.",
    "n": "Number of top rows to return. Ranks and shares still use the full list.",
    "spike_factor": (
        "A month is a spike if its blocked count is at least this many times "
        "the median month."
    ),
}

# Types the model sees, where they are stricter than the Python annotation.
PARAM_TYPES = {
    "year": (int, {}),
    "product": (str, {}),
    "attack_type": (AttackType, {}),
    "n": (int, {"ge": 1}),
    "spike_factor": (float, {"gt": 0}),
}


def _args_schema(func):
    """Pydantic model of the function's parameters, with descriptions and constraints."""
    fields = {}
    for name, param in inspect.signature(func).parameters.items():
        if name not in PARAM_TYPES:
            raise ValueError(f"{func.__name__}: no schema for parameter {name!r}")
        type_, constraints = PARAM_TYPES[name]
        required = param.default is inspect.Parameter.empty
        key = "product_optional" if name == "product" and not required else name
        if required:
            fields[name] = (type_, Field(..., description=PARAM_DESCRIPTIONS[key], **constraints))
        else:
            if param.default is None:
                type_ = Optional[type_]
            fields[name] = (type_, Field(param.default, description=PARAM_DESCRIPTIONS[key], **constraints))
    return create_model(f"{func.__name__}_args", **fields)


def _wrap(func):
    def run(**kwargs):
        try:
            return func(**kwargs)
        except ValueError as exc:  # bad argument: tell the model so it can retry
            raise ToolException(f"Invalid arguments for {func.__name__}: {exc}") from exc

    return StructuredTool.from_function(
        func=run,
        name=func.__name__,
        description=inspect.getdoc(func),
        args_schema=_args_schema(func),
        handle_tool_error=True,
        handle_validation_error=lambda exc: f"Invalid arguments for {func.__name__}: {exc}",
    )


TOOLS = [_wrap(f) for f in report_tools.TOOLS]
TOOLS_BY_NAME = {t.name: t for t in TOOLS}
