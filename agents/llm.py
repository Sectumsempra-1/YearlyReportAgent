"""Chat model client built from environment variables.

The model is reached through an OpenAI-compatible endpoint (Ollama for the
PoC, vLLM later). Configuration comes from the environment or a `.env` file in
the project root; see `.env.example`. Variables already set in the environment
take precedence over `.env`.
"""

import os
from pathlib import Path

from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"

DEFAULT_API_KEY = "not-needed"  # Ollama ignores the key, but the client requires one
TIMEOUT_SECONDS = 300  # local models can be slow on long prompts
MAX_RETRIES = 2  # network-level retries only

# Rule 7: nothing may leave the machine while the pipeline runs. LangSmith is
# installed as a langchain dependency, so its tracing is forced off here.
TRACING_VARS = ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2")


class LLMConfigError(RuntimeError):
    """Raised when the model configuration is missing or invalid."""


def disable_tracing() -> None:
    for name in TRACING_VARS:
        os.environ[name] = "false"


def get_llm() -> ChatOpenAI:
    """Return a chat model client built from LLM_BASE_URL, LLM_MODEL and LLM_API_KEY.

    LLM_BASE_URL is required: without it the client would fall back to
    OpenAI's commercial API, which rule 7 forbids. Base URL and key are passed
    explicitly so stray OPENAI_* variables cannot redirect the client.
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

    return ChatOpenAI(
        model=model,
        base_url=base_url,
        api_key=api_key,
        temperature=0,
        timeout=TIMEOUT_SECONDS,
        max_retries=MAX_RETRIES,
    )
