"""Structured JSON output from the model, validated by Pydantic.

Convention (CLAUDE.md): retry once on invalid JSON, then fail with a clear error.
"""

import json
import re

from langchain_core.messages import AIMessage, HumanMessage
from pydantic import BaseModel, ValidationError

THINK_RE = re.compile(r"<think>.*?</think>", re.S)


class StructuredOutputError(RuntimeError):
    """The model did not produce valid output after one retry."""


def text_of(message) -> str:
    content = message.content
    if isinstance(content, str):
        return content
    return "".join(p.get("text", "") if isinstance(p, dict) else str(p) for p in content)


def parse(text: str, model: type[BaseModel]) -> BaseModel:
    """Parse the JSON object in a reply. Ignores <think> blocks, code fences and text around it."""
    cleaned = THINK_RE.sub("", text)
    start, end = cleaned.find("{"), cleaned.rfind("}")
    if start == -1 or end < start:
        raise ValueError("no JSON object found in the reply")
    try:
        data = json.loads(cleaned[start:end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc}") from exc
    return model.model_validate(data)


def complete(llm, messages: list, model: type[BaseModel], reply: AIMessage | None = None) -> BaseModel:
    """Parse `reply` (or a new model reply) into `model`, retrying once with the error.

    `messages` is extended with the retry exchange, so the transcript stays complete.
    """
    if reply is None:
        reply = llm.invoke(messages)
        messages.append(reply)
    try:
        return parse(text_of(reply), model)
    except (ValueError, ValidationError) as first:
        messages.append(HumanMessage(
            "Your answer could not be used:\n"
            f"{first}\n\n"
            "Reply again with only the corrected JSON object, no other text."))
        retry = llm.invoke(messages)
        messages.append(retry)
        try:
            return parse(text_of(retry), model)
        except (ValueError, ValidationError) as second:
            raise StructuredOutputError(
                f"{model.__name__}: invalid output after one retry.\n"
                f"First error: {first}\nSecond error: {second}") from second
