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

Download the MITRE ATT&CK dataset the normalizer checks technique IDs
against (a pinned version, about 55 MB, saved to `data/reference/attack/`,
which is gitignored). This is a one-time setup step; the pipeline itself never
downloads anything and stops with a clear error if the file is missing:

```bash
python scripts/fetch_attack.py
```

**Ollama context size.** The agents need a larger context than Ollama's
default of 4096 tokens: with the default, tool results overflow it, Ollama
silently drops the oldest messages, and the agents loop and return empty
answers. Set it once for your user and restart Ollama (quit it from the tray
and start it again):

```powershell
[Environment]::SetEnvironmentVariable('OLLAMA_CONTEXT_LENGTH', '32768', 'User')
```

`ollama ps` shows the context in use (`CONTEXT` column) once a model is loaded.

Check that the model is reachable and supports tool calls:

```bash
python scripts/check_llm.py                   # uses LLM_MODEL from .env
python scripts/check_llm.py --model qwen3:8b  # try another model
```

It prints PASS or FAIL for a test message and a test tool call, and exits
with 0 only if both pass.

## Run

Load the product deliveries into `data/report.db` (set `REPORT_DB` to use
another path):

```bash
python ingest.py                     # loads data/exports
python ingest.py data/exports_bad    # the broken delivery: must be rejected
```

Each file is printed as `LOADED`, `SKIPPED` (identical file already loaded) or
`REJECTED` (with its errors). A file with any error loads nothing.
Rejections are also appended to `ingest_errors.log`. The exit code is 0 if
nothing was rejected, 1 if a file was rejected, and 2 on a usage or reference
data error.

Print a demo of every query function in `report_tools.py` for 2026 (needs
the database from `ingest.py`):

```bash
python report_tools.py
```

Run the report pipeline:

```bash
python run_report.py --year 2026
```

The pipeline pauses twice for approval: after the outline and before the
report is published. At each pause, answer `a` (approve), `r` (reject with a
comment, which sends the outline or the executive summary back to be
rewritten) or `b` (abort). Each section gets up to 4 attempts at passing
verification; if one still fails, the run stops and lists the failures.

Every run writes all of its outputs to `runs/<run_id>/` (findings, outline
versions, each section attempt and its verification result, approvals,
`report.md` with finding tags and `report_clean.md` without). The exit code
is 0 when the report is written, 1 when a section failed verification and 3
when the run was aborted.

> **Status:** the analysts, normalizer, synthesizer, section writers,
> verifier and executive summary are still stubs that return fixed fake data
> (marked `STUB`). They are replaced with real agents step by step.

Run the tests:

```bash
pytest
```
