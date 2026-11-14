# Yearly security report PoC

A multi-agent system that generates a yearly report on our security products:
attacks blocked, top malware, attack source countries, and trends. It runs on
open-source components and a self-hosted model, using dummy data.

- Design: [`docs/SPEC.md`](docs/SPEC.md)
- Project rules: [`CLAUDE.md`](CLAUDE.md)
- Dummy product data: `data/`

## Setup

Requires Python 3.11 or newer (tested on 3.14).

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows; on Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # then set LLM_MODEL to a model you have pulled in Ollama
```

Check that the model is reachable and supports tool calls:

```bash
python scripts/check_llm.py                   # uses LLM_MODEL from .env
python scripts/check_llm.py --model qwen3:8b  # try another model
```

It prints PASS or FAIL for a test message and a test tool call, and exits
with 0 only if both pass.

## Run

```bash
pytest
```

More commands (ingestion, the pipeline) will be added as each part is built.
