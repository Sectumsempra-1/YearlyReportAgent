"""Chat model client built from environment variables.

The model is reached through an OpenAI-compatible endpoint (Ollama for the
PoC, vLLM later). Configuration comes from the environment or a `.env` file in
the project root; see `.env.example`. Variables already set in the environment
take precedence over `.env`.
"""

import os
import threading
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

DEFAULT_API_KEY = "not-needed"  # Ollama ignores the key, but the client requires one
TIMEOUT_SECONDS = 900  # one request; a local model with reasoning on a long prompt is slow
MAX_RETRIES = 0  # a timed-out request is not retried: retrying a slow model only multiplies the wait

# How much a reasoning model thinks before answering. Measured on qwen3.5:9b:
# "none" is fast but maps ATT&CK techniques wrongly; the model's default
# (full thinking) is ~10x slower than "low" with no better answers.
REASONING_EFFORTS = ("none", "low", "medium", "high")
DEFAULT_REASONING_EFFORT = "low"

# Longest reply, reasoning included. A model stuck repeating itself then fails
# in minutes with a clear error instead of running into the timeout.
DEFAULT_MAX_TOKENS = 8000

# Rule 7: nothing may leave the machine while the pipeline runs. LangSmith is
# installed as a langchain dependency, so its tracing is forced off here.
TRACING_VARS = ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2")


# Requests sent to the server at the same time. Ollama on one GPU works on one
# request at a time and queues the rest, and a queued request's wait counts
# against its timeout: with 5 section writers in parallel the last ones timed
# out before they started. Waiting here instead keeps the timeout for the work.
# Raise it for a server that batches requests (vLLM).
DEFAULT_MAX_PARALLEL = 1
_slots: dict[int, threading.Semaphore] = {}
_slots_lock = threading.Lock()


def _slot(limit: int) -> threading.Semaphore:
    with _slots_lock:
        return _slots.setdefault(limit, threading.Semaphore(limit))


class LimitedChatOpenAI(ChatOpenAI):
    """ChatOpenAI that sends at most max_parallel requests at once (per process)."""

    max_parallel: int = DEFAULT_MAX_PARALLEL

    def _generate(self, *args, **kwargs):
        with _slot(self.max_parallel):
            return super()._generate(*args, **kwargs)


class LLMConfigError(RuntimeError):
    """Raised when the model configuration is missing or invalid."""


def disable_tracing() -> None:
    for name in TRACING_VARS:
        os.environ[name] = "false"


def _env_number(name: str, cast, minimum):
    raw = os.environ.get(name, "").strip()
    if not raw:
        return None
    try:
        value = cast(raw)
    except ValueError:
        raise LLMConfigError(f"{name} must be a number, got {raw!r}") from None
    if value < minimum:
        raise LLMConfigError(f"{name} must be at least {minimum}, got {raw!r}")
    return value


def get_llm(reasoning_effort: str | None = None) -> ChatOpenAI:
    """Return a chat model client built from LLM_BASE_URL, LLM_MODEL, LLM_API_KEY,
    LLM_REASONING_EFFORT, LLM_TEMPERATURE, LLM_MAX_TOKENS and LLM_MAX_PARALLEL.

    LLM_BASE_URL is required: without it the client would fall back to
    OpenAI's commercial API, which rule 7 forbids. Base URL and key are passed
    explicitly so stray OPENAI_* variables cannot redirect the client.

    reasoning_effort lets a node ask for a different effort than the default
    (e.g. the normalizer uses "none"). It is ignored when LLM_REASONING_EFFORT
    is set to empty, i.e. when the server does not support it.

    Temperature is only sent when LLM_TEMPERATURE is set; otherwise the
    model's own sampling settings apply. Forcing 0 made a reasoning model
    repeat itself until it ran out of tokens.
    """
    load_dotenv(ENV_FILE, override=False)
    disable_tracing()

    base_url = os.environ.get("LLM_BASE_URL", "").strip()
    model = os.environ.get("LLM_MODEL", "").strip()
    missing = [name for name, value in (("LLM_BASE_URL", base_url), ("LLM_MODEL", model)) if not value]
    if missing:
        raise LLMConfigError(
            f"Missing environment variable(s): {', '.join(missing)}. "
            "Copy .env.example to .env and set them."
        )
    api_key = os.environ.get("LLM_API_KEY", "").strip() or DEFAULT_API_KEY

    # Unset: the default. Set but empty: not sent (for servers that do not support it).
    effort = os.environ.get("LLM_REASONING_EFFORT", DEFAULT_REASONING_EFFORT).strip().lower()
    if effort and reasoning_effort is not None:
        effort = reasoning_effort.strip().lower()
    if effort and effort not in REASONING_EFFORTS:
        raise LLMConfigError(
            f"reasoning effort must be one of {', '.join(REASONING_EFFORTS)} or empty, got {effort!r} "
            "(LLM_REASONING_EFFORT)")
    extra = {"reasoning_effort": effort} if effort else {}

    temperature = _env_number("LLM_TEMPERATURE", float, 0)
    if temperature is not None:
        extra["temperature"] = temperature
    max_tokens = _env_number("LLM_MAX_TOKENS", int, 1) or DEFAULT_MAX_TOKENS
    max_parallel = _env_number("LLM_MAX_PARALLEL", int, 1) or DEFAULT_MAX_PARALLEL

    return LimitedChatOpenAI(
        model=model,
        base_url=base_url,
        api_key=api_key,
        timeout=TIMEOUT_SECONDS,
        max_retries=MAX_RETRIES,
        max_tokens=max_tokens,
        max_parallel=max_parallel,
        **extra,
    )
