"""Product analyst (SPEC 7.1): one per product, in parallel.

The model explores the product's data with the report_tools tools, then
answers with findings as JSON (validated by Pydantic, one retry on invalid
output). Code then:

- sets each finding's product (the model does not)
- checks every finding against its cited tool call (agents/finding_check.py)
  and drops, and logs, findings that fail

Input (sent by the graph): {"year", "run_dir", "product"}.
Output: {"drafts": [FindingDraft, ...]}.

Saved to the run folder: analyst_<product>.json (kept findings),
analyst_<product>_dropped.json (dropped findings and why), and
analyst_<product>_transcript.json (every tool call, its result, and the replies).
"""

import json
import logging

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from agents.finding_check import check_finding
from agents.prompt_loader import load_prompt
from agents.runs import save, slug
from agents.state import AnalystOutput, FindingDraft
from agents.structured import complete, text_of
from agents.tools import TOOLS, TOOLS_BY_NAME

log = logging.getLogger(__name__)

MAX_TOOL_ROUNDS = 15  # model turns that may call tools before a final answer is required


def run_tool_loop(llm, messages: list, transcript: list, max_rounds: int = MAX_TOOL_ROUNDS) -> AIMessage:
    """Let the model call tools until it answers without tool calls. Returns that answer."""
    model = llm.bind_tools(TOOLS)
    seen: set[str] = set()
    for _ in range(max_rounds):
        reply = model.invoke(messages)
        messages.append(reply)
        if not reply.tool_calls:
            return reply
        for call in reply.tool_calls:
            key = json.dumps([call["name"], call["args"]], sort_keys=True, default=str)
            tool = TOOLS_BY_NAME.get(call["name"])
            if key in seen:
                # Same call again: point back instead of repeating a long result.
                content = ("You already made this exact call; its result is earlier in this "
                           "conversation. Use it, or call a different tool or arguments.")
                transcript.append({"tool": call["name"], "args": call["args"], "result": "(repeat)"})
            else:
                result = (tool.invoke(call["args"]) if tool
                          else f"Unknown tool {call['name']!r}. Available: {', '.join(TOOLS_BY_NAME)}")
                transcript.append({"tool": call["name"], "args": call["args"], "result": result})
                # Compact JSON: tool results are the bulk of the context window.
                content = result if isinstance(result, str) else json.dumps(
                    result, ensure_ascii=False, separators=(",", ":"))
                seen.add(key)
            messages.append(ToolMessage(content=content, tool_call_id=call["id"]))
    messages.append(HumanMessage(
        "You have used all your tool calls. Give your final answer now, as the JSON object only."))
    reply = llm.invoke(messages)
    messages.append(reply)
    return reply


def check_drafts(drafts: list[FindingDraft], scope_product: str | None) -> tuple[list, list]:
    kept, dropped = [], []
    for draft in drafts:
        problems = check_finding(draft, scope_product)
        if problems:
            dropped.append({"finding": draft, "problems": problems})
            log.warning("dropped finding %r: %s", draft.statement, "; ".join(problems))
        else:
            kept.append(draft)
    return kept, dropped


def run_analyst(llm, year: int, product: str | None, prompt_name: str, run_dir: str, file_stem: str,
                max_rounds: int = MAX_TOOL_ROUNDS) -> list[FindingDraft]:
    """Explore, answer, check. Shared by the product and cross-product analysts.

    product is the analyst's scope: a product name, or None for all products.
    """
    system = load_prompt(prompt_name, product=product or "", year=year, previous_year=year - 1)
    task = (f"Analyse {product} for {year}." if product
            else f"Analyse all products together for {year}.")
    messages = [SystemMessage(system), HumanMessage(task)]
    transcript: list = []
    try:
        answer = run_tool_loop(llm, messages, transcript, max_rounds)
        output = complete(llm, messages, AnalystOutput, reply=answer)
    finally:
        save(run_dir, f"{file_stem}_transcript.json",
             {"tool_calls": transcript,
              "replies": [text_of(m) for m in messages if isinstance(m, AIMessage) and text_of(m)]})

    drafts = [FindingDraft(**f.model_dump(), product=product or "ALL") for f in output.findings]
    kept, dropped = check_drafts(drafts, product)
    save(run_dir, f"{file_stem}.json", kept)
    save(run_dir, f"{file_stem}_dropped.json", dropped)
    return kept


def make_analyst(llm=None):
    """Build the analyst node. Without an llm, the client comes from agents.llm at run time."""

    def analyst(payload: dict) -> dict:
        from agents.llm import get_llm
        model = llm or get_llm()
        product = payload["product"]
        kept = run_analyst(model, payload["year"], product, "analyst", payload["run_dir"],
                           f"analyst_{slug(product)}")
        return {"drafts": kept}

    return analyst


analyst = make_analyst()
