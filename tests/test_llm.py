"""Tests for agents/llm.py. No model is called."""

import pytest

from agents import llm as llm_module
from agents.llm import DEFAULT_API_KEY, LLMConfigError, get_llm


@pytest.fixture(autouse=True)
def clean_env(monkeypatch, tmp_path):
    """Isolate each test from the real environment and the real .env file."""
    monkeypatch.setattr(llm_module, "ENV_FILE", tmp_path / "missing.env")
    for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY", "OPENAI_BASE_URL",
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
    assert client.temperature == 0


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
