"""Test doubles: a scripted chat model and stub nodes. No model is called."""

import json

from langchain_core.messages import AIMessage

from agents.runs import save, slug
from agents.state import FindingDraft, NormalizedFinding, Source, TechniqueMapping


class FakeChatModel:
    """Returns scripted replies in order and records every message list it was given.

    A reply is an AIMessage, a str (plain answer), a dict (sent as JSON text),
    or a list of (tool_name, args) tuples (tool calls).
    """

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[list] = []
        self.bound_tools = None
        self.bound_kwargs = {}

    def bind_tools(self, tools):
        self.bound_tools = tools
        return self

    def bind(self, **kwargs):
        self.bound_kwargs = kwargs
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


def stub_normalizer(state: dict) -> dict:
    """The former normalizer stub: fixed mappings, one below the review threshold."""
    from agents.nodes.normalizer import apply_confidence_threshold
    stub = []
    for i, f in enumerate(state["findings"]):
        mappings = [TechniqueMapping(technique_id="T1190", name="stub", confidence=0.9)]
        if i == 0:
            mappings.append(TechniqueMapping(technique_id="T1566", name="stub", confidence=0.5))
        stub.append(NormalizedFinding(**f.model_dump(), attack_techniques=mappings, confidence=0.8))
    normalized, review = apply_confidence_threshold(stub)
    save(state["run_dir"], "normalized.json", normalized)
    save(state["run_dir"], "review.json", review)
    return {"normalized": normalized}


def stub_synthesizer(state: dict) -> dict:
    """The former synthesizer stub: a fixed outline spreading findings over the sections."""
    from agents.runs import next_version
    from agents.state import OUTLINE_SECTIONS, SECTION_TITLES, Outline
    ids = [f.id for f in state["normalized"]]
    thesis = "STUB thesis."
    if state.get("outline_feedback"):
        thesis += f" Revised after review: {state['outline_feedback']}"
    outline = Outline(
        thesis=thesis,
        signature_metric={"finding_id": ids[0], "value_key": next(iter(state["normalized"][0].values), "")},
        themes=[{"title": f"STUB theme {n}", "summary": "STUB summary.", "finding_ids": [ids[n % len(ids)]]}
                for n in range(3)],
        sections=[{"id": sid, "title": SECTION_TITLES[sid], "goal": "STUB goal.",
                   "finding_ids": [ids[n % len(ids)]]} for n, sid in enumerate(OUTLINE_SECTIONS)],
    )
    save(state["run_dir"], f"outline_{next_version(state['run_dir'], 'outline')}.json", outline)
    return {"outline": outline}


def stub_section_writer(state: dict) -> dict:
    """The former writer stub: fixed Markdown quoting the first assigned finding."""
    from agents.state import Section
    finding = state["findings"][0]
    key, value = next(iter(finding.values.items()), ("", ""))
    markdown = f"STUB {state['title']} (attempt {state['attempt']}). {key}: {value} [{finding.id}]."
    return {"draft": Section(id=state["section_id"], title=state["title"], markdown=markdown,
                             finding_ids_used=[finding.id])}


def stub_verifier(state: dict) -> dict:
    """The former verifier stub: every draft passes."""
    from agents.state import VerificationResult
    return {"verification": VerificationResult(section_id=state["section_id"], passed=True)}
