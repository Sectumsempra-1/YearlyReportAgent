"""Tests for agents/llm.py. No model is called."""

import pytest

from agents import llm as llm_module
from agents.llm import DEFAULT_API_KEY, LLMConfigError, get_llm


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """Isolate each test from the real environment and the real .env file."""
    monkeypatch.setattr(llm_module, "ENV_FILE", tmp_path / "missing.env")
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "LLM_REASONING_EFFORT", "LLM_TEMPERATURE", "LLM_MAX_TOKENS", "LLM_MAX_PARALLEL", "OPENAI_BASE_URL",
                 "OPENAI_API_BASE", "OPENAI_API_KEY", *llm_module.TRACING_VARS):
        monkeypatch.delenv(name, raising=False)


def set_config(monkeypatch, **values):
    for name, value in values.items():
        monkeypatch.setenv(name, value)


def test_builds_client_from_env(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1",
               LLM_MODEL="some-model", LLM_API_KEY="secret")
    client = get_llm()
    assert client.openai_api_base == "http://localhost:11434/v1"
    assert client.model_name == "some-model"
    assert client.openai_api_key.get_secret_value() == "secret"
    assert client.temperature is None          # the model's own sampling settings
    assert client.max_tokens == llm_module.DEFAULT_MAX_TOKENS


def test_default_api_key(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m")
    assert get_llm().openai_api_key.get_secret_value() == DEFAULT_API_KEY


@pytest.mark.parametrize("missing", ["LLM_BASE_URL", "LLM_MODEL"])
def test_missing_variable_raises(monkeypatch, missing):
    values = {"LLM_BASE_URL": "http://localhost:11434/v1", "LLM_MODEL": "m"}
    del values[missing]
    set_config(monkeypatch, **values)
    with pytest.raises(LLMConfigError, match=missing):
        get_llm()


def test_blank_base_url_raises(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="   ", LLM_MODEL="m")
    with pytest.raises(LLMConfigError, match="LLM_BASE_URL"):
        get_llm()


def test_openai_env_vars_cannot_redirect(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m",
               OPENAI_BASE_URL="https://api.openai.com/v1", OPENAI_API_KEY="sk-real")
    client = get_llm()
    assert client.openai_api_base == "http://localhost:11434/v1"
    assert client.openai_api_key.get_secret_value() == DEFAULT_API_KEY


def test_tracing_forced_off(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m",
               LANGSMITH_TRACING="true", LANGCHAIN_TRACING_V2="true")
    get_llm()
    import os
    for name in llm_module.TRACING_VARS:
        assert os.environ[name] == "false"


def test_env_file_is_read_but_env_wins(monkeypatch, tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_BASE_URL=http://from-file/v1\nLLM_MODEL=file-model\n")
    monkeypatch.setattr(llm_module, "ENV_FILE", env_file)
    set_config(monkeypatch, LLM_MODEL="env-model")
    client = get_llm()
    assert client.openai_api_base == "http://from-file/v1"
    assert client.model_name == "env-model"


def test_reasoning_effort_defaults_to_low(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m")
    monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
    assert get_llm().reasoning_effort == "low"


@pytest.mark.parametrize("value, expected", [("high", "high"), (" None ", "none"), ("", None)])
def test_reasoning_effort_from_env(monkeypatch, value, expected):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m",
               LLM_REASONING_EFFORT=value)
    assert get_llm().reasoning_effort == expected


def test_invalid_reasoning_effort(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m",
               LLM_REASONING_EFFORT="extreme")
    with pytest.raises(LLMConfigError, match="LLM_REASONING_EFFORT"):
        get_llm()


def test_timeouts_are_not_retried(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m")
    client = get_llm()
    assert client.max_retries == 0 and client.request_timeout == llm_module.TIMEOUT_SECONDS


def test_node_can_override_reasoning_effort(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m")
    assert get_llm(reasoning_effort="none").reasoning_effort == "none"
    with pytest.raises(LLMConfigError, match="reasoning effort"):
        get_llm(reasoning_effort="max")


def test_override_ignored_when_server_does_not_support_reasoning(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m", LLM_REASONING_EFFORT="")
    assert get_llm(reasoning_effort="none").reasoning_effort is None


@pytest.mark.parametrize("name, value, attr, expected", [
    ("LLM_TEMPERATURE", "0.6", "temperature", 0.6),
    ("LLM_TEMPERATURE", "0", "temperature", 0.0),
    ("LLM_MAX_TOKENS", "2000", "max_tokens", 2000),
])
def test_numeric_settings(monkeypatch, name, value, attr, expected):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m", **{name: value})
    assert getattr(get_llm(), attr) == expected


@pytest.mark.parametrize("name, value", [
    ("LLM_TEMPERATURE", "warm"), ("LLM_TEMPERATURE", "-1"), ("LLM_MAX_TOKENS", "0"), ("LLM_MAX_TOKENS", "1.5"),
])
def test_invalid_numeric_settings(monkeypatch, name, value):
    set_config(monkeypatch, LLM_BASE_URL="http://localhost:11434/v1", LLM_MODEL="m", **{name: value})
    with pytest.raises(LLMConfigError, match=name):
        get_llm()


def test_max_parallel_default_and_env(monkeypatch):
    set_config(monkeypatch, LLM_BASE_URL="http://x/v1", LLM_MODEL="m")
    assert get_llm().max_parallel == llm_module.DEFAULT_MAX_PARALLEL == 1
    monkeypatch.setenv("LLM_MAX_PARALLEL", "4")
    assert get_llm().max_parallel == 4
    monkeypatch.setenv("LLM_MAX_PARALLEL", "0")
    with pytest.raises(LLMConfigError, match="LLM_MAX_PARALLEL"):
        get_llm()


def test_requests_wait_for_a_free_slot(monkeypatch):
    """With max_parallel=1, two threads never send at the same time."""
    import threading
    import time

    from langchain_openai import ChatOpenAI

    running, most = [0], [0]
    lock = threading.Lock()

    def fake_generate(self, *args, **kwargs):
        with lock:
            running[0] += 1
            most[0] = max(most[0], running[0])
        time.sleep(0.05)
        with lock:
            running[0] -= 1
        return "ok"

    monkeypatch.setattr(ChatOpenAI, "_generate", fake_generate)
    set_config(monkeypatch, LLM_BASE_URL="http://x/v1", LLM_MODEL="m")
    client = get_llm()
    threads = [threading.Thread(target=client._generate, args=([],)) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert most[0] == 1
