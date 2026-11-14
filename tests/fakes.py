"""Test doubles: a scripted chat model and stub nodes. No model is called."""

import json

from langchain_core.messages import AIMessage

from agents.runs import save, slug
from agents.state import FindingDraft, Source


class FakeChatModel:
    """Returns scripted replies in order and records every message list it was given.

    A reply is an AIMessage, a str (plain answer), a dict (sent as JSON text),
    or a list of (tool_name, args) tuples (tool calls).
    """

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[list] = []
        self.bound_tools = None

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self

    def invoke(self, messages):
        self.calls.append(list(messages))
        if not self.replies:
            raise AssertionError("FakeChatModel ran out of scripted replies")
        reply = self.replies.pop(0)
        if isinstance(reply, AIMessage):
            return reply
        if isinstance(reply, dict):
            return AIMessage(content=json.dumps(reply))
        if isinstance(reply, list):
            return AIMessage(content="", tool_calls=[
                {"name": name, "args": args, "id": f"call_{len(self.calls)}_{i}"}
                for i, (name, args) in enumerate(reply)])
        return AIMessage(content=reply)


def stub_analyst(payload: dict) -> dict:
    """The former analyst stub: fixed fake findings, for graph tests."""
    year, product = payload["year"], payload["product"]
    drafts = [
        FindingDraft(product=product, statement=f"STUB: {product} blocked attacks in {year}.",
                     values={"blocked": 1000},
                     source=Source(function="attacks_blocked",
                                   params={"year": year, "product": product, "attack_type": None},
                                   key_paths={"blocked": "value"})),
        FindingDraft(product=product, statement=f"STUB: {product} blocked attacks changed.",
                     values={"pct_change": 12.5},
                     source=Source(function="compare_years",
                                   params={"year": year, "product": product, "attack_type": None},
                                   key_paths={"pct_change": "value.pct_change"})),
    ]
    save(payload["run_dir"], f"analyst_{slug(product)}.json", drafts)
    return {"drafts": drafts}
