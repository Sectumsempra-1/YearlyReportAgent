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

## Run

```bash
pytest
```

More commands (ingestion, the pipeline) will be added as each part is built.
