"""Tests for agents/tools.py. No model is called."""

import inspect
import io
import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

import ingest
import report_tools
from agents.tools import PARAM_DESCRIPTIONS, TOOLS, TOOLS_BY_NAME

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    code = ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO())
    assert code == 0
    return db


@pytest.fixture
def db(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


def schema(tool) -> dict:
    """The JSON schema the model is given for this tool."""
    return convert_to_openai_tool(tool)["function"]["parameters"]


# --- one tool per function, with the docstring as description -----------------------------

def test_one_tool_per_function_in_same_order():
    assert [t.name for t in TOOLS] == [f.__name__ for f in report_tools.TOOLS]
    assert set(TOOLS_BY_NAME) == {f.__name__ for f in report_tools.TOOLS}


@pytest.mark.parametrize("func", report_tools.TOOLS, ids=lambda f: f.__name__)
def test_description_is_the_docstring(func):
    assert TOOLS_BY_NAME[func.__name__].description == inspect.getdoc(func)
    assert func.__doc__, f"{func.__name__} has no docstring"


# --- schemas -------------------------------------------------------------------------------

@pytest.mark.parametrize("func", report_tools.TOOLS, ids=lambda f: f.__name__)
def test_schema_matches_signature(func):
    s = schema(TOOLS_BY_NAME[func.__name__])
    params = inspect.signature(func).parameters
    assert set(s["properties"]) == set(params)
    required = {n for n, p in params.items() if p.default is inspect.Parameter.empty}
    assert set(s.get("required", [])) == required
    for name, param in params.items():
        prop = s["properties"][name]
        assert prop.get("description"), f"{func.__name__}.{name} has no description"
        if param.default is not inspect.Parameter.empty:
            assert prop["default"] == param.default


def test_parameter_types():
    s = schema(TOOLS_BY_NAME["monthly_series"])["properties"]
    assert s["year"]["type"] == "integer"
    assert {"type": "string"} in s["product"]["anyOf"] and {"type": "null"} in s["product"]["anyOf"]
    enum = next(x for x in s["attack_type"]["anyOf"] if "enum" in x)["enum"]
    assert enum == sorted(ingest.ATTACK_TYPES)
    assert s["spike_factor"]["type"] == "number" and s["spike_factor"]["exclusiveMinimum"] == 0

    n = schema(TOOLS_BY_NAME["top_malware"])["properties"]["n"]
    assert (n["type"], n["minimum"], n["default"]) == ("integer", 1, 10)


def test_product_is_required_for_product_summary():
    s = schema(TOOLS_BY_NAME["product_summary"])
    assert s["required"] == ["year", "product"]
    assert s["properties"]["product"] == {
        "description": PARAM_DESCRIPTIONS["product"], "type": "string"}


def test_list_products_takes_no_arguments():
    assert schema(TOOLS_BY_NAME["list_products"])["properties"] == {}


def test_descriptions_do_not_mention_data():
    """Rule 8: descriptions explain parameters; they must not reveal what the data contains."""
    text = " ".join(PARAM_DESCRIPTIONS.values())
    for word in ("2025", "2026", "EDR", "Firewall", "Email Gateway"):
        assert word not in text


# --- results ---------------------------------------------------------------------------------

@pytest.mark.parametrize("name, args", [
    ("list_products", {}),
    ("attacks_blocked", {"year": 2026}),
    ("compare_years", {"year": 2026, "product": "EDR", "attack_type": "ransomware"}),
    ("product_summary", {"year": 2026, "product": "Firewall"}),
    ("attack_type_changes", {"year": 2026}),
    ("top_malware", {"year": 2026, "n": 3}),
    ("unmapped_malware", {"year": 2026}),
    ("top_countries", {"year": 2026}),
    ("monthly_series", {"year": 2026, "spike_factor": 1.2}),
    ("sector_breakdown", {"year": 2026}),
    ("severity_breakdown", {"year": 2026, "product": "EDR"}),
])
def test_tool_returns_the_full_result(db, name, args):
    result = TOOLS_BY_NAME[name].invoke(args)
    assert result == getattr(report_tools, name)(**args)
    assert set(result) == {"value", "source", "caveats"}


def test_defaults_are_filled_in(db):
    result = TOOLS_BY_NAME["top_malware"].invoke({"year": 2026})
    assert result["source"]["params"] == {"year": 2026, "n": 10, "product": None}


def test_caveats_are_kept(db):
    result = TOOLS_BY_NAME["top_countries"].invoke({"year": 2026})
    assert report_tools.CAVEAT_GEOLOCATION in result["caveats"]
    assert report_tools.CAVEAT_CROSS_PRODUCT in result["caveats"]


# --- errors go back to the model ---------------------------------------------------------------

@pytest.mark.parametrize("name, args, expected", [
    ("attacks_blocked", {"year": 2026, "product": "Nope"}, "unknown product 'Nope'; valid products:"),
    ("attacks_blocked", {"year": 2026, "attack_type": "ddos"}, "attack_type"),
    ("top_malware", {"year": 2026, "n": 0}, "greater than or equal to 1"),
    ("monthly_series", {"year": 2026, "spike_factor": -1}, "greater than 0"),
    ("product_summary", {"year": 2026}, "product"),
    ("attacks_blocked", {"year": "next year"}, "year"),
])
def test_bad_arguments_return_an_error_message(db, name, args, expected):
    result = TOOLS_BY_NAME[name].invoke(args)
    assert isinstance(result, str)
    assert result.startswith(f"Invalid arguments for {name}:")
    assert expected in result


def test_missing_database_is_raised(tmp_path, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(tmp_path / "missing.db"))
    with pytest.raises(FileNotFoundError):
        TOOLS_BY_NAME["attacks_blocked"].invoke({"year": 2026})


# --- inside a LangGraph ToolNode -------------------------------------------------------------------

def run_tool_node(call: AIMessage) -> list:
    """Run the tools in a one-node graph, the way the agents will use them."""
    graph = StateGraph(MessagesState)
    graph.add_node("tools", ToolNode(TOOLS))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    return graph.compile().invoke({"messages": [call]})["messages"][1:]


def test_tool_node_returns_json_result(db):
    call = AIMessage(content="", tool_calls=[
        {"name": "compare_years", "args": {"year": 2026, "product": "EDR"}, "id": "c1"},
        {"name": "top_malware", "args": {"year": 2026, "n": 2}, "id": "c2"},
    ])
    messages = run_tool_node(call)
    assert [m.tool_call_id for m in messages] == ["c1", "c2"]
    first = json.loads(messages[0].content)
    assert first == report_tools.compare_years(2026, product="EDR")
    second = json.loads(messages[1].content)
    assert second["source"]["params"] == {"year": 2026, "n": 2, "product": None}
    assert len(second["value"]["rows"]) == 2


def test_tool_node_passes_errors_to_the_model(db):
    call = AIMessage(content="", tool_calls=[
        {"name": "attacks_blocked", "args": {"year": 2026, "product": "Nope"}, "id": "c1"}])
    message = run_tool_node(call)[0]
    assert "unknown product 'Nope'" in message.content
