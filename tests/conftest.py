"""Shared test setup."""

import pytest

import agents.llm


@pytest.fixture(autouse=True)
def no_real_model(monkeypatch):
    """Tests use fake models. A node that would build a real client fails at once instead of
    calling Ollama (and hanging for minutes). Tests that need get_llm patch it themselves."""

    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to call a real model; pass a fake model or a stub node")

    monkeypatch.setattr(agents.llm, "get_llm", refuse)


@pytest.fixture(autouse=True)
def run_in_tmp(tmp_path_factory, monkeypatch):
    """Every test runs in a temporary folder, so a stray relative path cannot write into the project."""
    monkeypatch.chdir(tmp_path_factory.mktemp("cwd"))
