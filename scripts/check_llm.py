"""Check that the configured model answers a message and makes a tool call.

Usage:
    python scripts/check_llm.py                  # model from LLM_MODEL
    python scripts/check_llm.py --model qwen3:8b # try another model

Exits with 0 only if both checks pass.
"""

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.tools import tool  # noqa: E402

from agents.llm import LLMConfigError, get_llm  # noqa: E402


@tool
def echo(text: str) -> str:
    """Return the given text unchanged."""
    return text


def _text(content) -> str:
    """Message content can be a string or a list of content parts."""
    if isinstance(content, str):
        return content
    return "".join(part.get("text", "") if isinstance(part, dict) else str(part) for part in content)


def check_message(llm) -> tuple[bool, str]:
    reply = _text(llm.invoke("Reply with the single word OK and nothing else.").content).strip()
    return bool(reply), f"reply: {reply[:80]!r}"


def check_tool_call(llm) -> tuple[bool, str]:
    reply = llm.bind_tools([echo]).invoke(
        'Call the echo tool with text set to "ping". Do not answer in plain text.'
    )
    calls = reply.tool_calls
    ok = any(c["name"] == "echo" and c["args"].get("text") == "ping" for c in calls)
    detail = f"tool calls: {calls}" if calls else f"no tool call; reply: {_text(reply.content)[:80]!r}"
    return ok, detail


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", help="override LLM_MODEL for this check")
    args = parser.parse_args()
    if args.model:
        os.environ["LLM_MODEL"] = args.model

    try:
        llm = get_llm()
    except LLMConfigError as exc:
        print(f"CONFIG ERROR: {exc}")
        return 1

    print(f"Endpoint: {llm.openai_api_base}")
    print(f"Model:    {llm.model_name}")

    all_ok = True
    for name, check in (("message", check_message), ("tool call", check_tool_call)):
        try:
            ok, detail = check(llm)
        except Exception as exc:  # report any failure, keep going
            ok, detail = False, f"{type(exc).__name__}: {exc}"
        all_ok &= ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<9}  {detail}")

    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
