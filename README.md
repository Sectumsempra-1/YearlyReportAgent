# Yearly security report PoC

A multi-agent system that writes a yearly report on our security products:
attacks blocked per product, top malware families, attack source countries,
and trends. Agents analyse aggregated data through read-only queries; plain
code checks every number before it reaches the report. Everything runs on
open-source components and a self-hosted model. This proof of concept uses
dummy data.

- Design: [`docs/SPEC.md`](docs/SPEC.md) (the source of truth)
- Project rules: [`CLAUDE.md`](CLAUDE.md)
- Dummy product data: `data/` (do not edit)

## How it works

```
data/exports/*.csv -> ingest.py (validation) -> data/report.db (SQLite)
  -> product analysts + cross-product analyst   (read-only tools from report_tools.py)
  -> normalizer (MITRE ATT&CK) -> synthesizer (outline)
  -> [you approve the outline]
  -> section writers, in parallel (no tools) -> verifier (up to 4 attempts each)
  -> executive summary -> verifier
  -> [you approve the report]
  -> report.md (with finding tags) and report_clean.md
```

Models never calculate. Every number comes from a query, is tagged with the
finding it came from (`rose 12.4% [F-007]`), and `verify.py` re-runs the
query to check it. Caveats from the queries and gaps in the data are stated
in the report, never dropped.

> **Status:** every step is real except the cross-product analyst, which
> still returns fixed fake findings (marked `STUB`), so findings that compare
> all products together are placeholders for now.

## Requirements

- Python 3.11 or newer (tested on 3.14)
- [Ollama](https://ollama.com) with a model that supports tool calls. The
  default is `qwen3.5:9b`. `python scripts/check_llm.py` tells you whether a
  model works.
- A GPU helps a lot. On an 8 GB GPU, expect a full run to take an hour or more
  (an estimate from timing the steps separately).
- Internet access only for setup (packages, model, ATT&CK dataset). The
  pipeline itself makes no external calls.

## Setup

All commands are run from the project folder. On Windows, the commands
below work in PowerShell; on Linux or macOS use `source .venv/bin/activate`
and `cp` instead of `copy`.

### 1. Python environment

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configuration

```powershell
copy .env.example .env
```

Edit `.env` if needed:

| Variable | Default | Meaning |
|---|---|---|
| `LLM_BASE_URL` | `http://localhost:11434/v1` | OpenAI-compatible endpoint (Ollama now, vLLM later). Required. |
| `LLM_MODEL` | `qwen3.5:9b` | Model name as the server knows it. Required. |
| `LLM_API_KEY` | `not-needed` | Ollama ignores it. |
| `LLM_REASONING_EFFORT` | `low` | How much a reasoning model thinks: `none`, `low`, `medium`, `high`. Leave empty if the server does not support it. The normalizer and the wording check always use `none`. |
| `LLM_TEMPERATURE` | unset | Unset uses the model's own sampling. Do not set 0 for reasoning models: they can repeat themselves endlessly. |
| `LLM_MAX_TOKENS` | `8000` | Longest reply, reasoning included. |
| `REPORT_DB` | `data/report.db` | SQLite database (relative paths are from the project folder). |
| `LANGSMITH_TRACING`, `LANGCHAIN_TRACING_V2` | `false` | Tracing stays off (no external calls). |

### 3. Ollama

Pull the model and raise Ollama's context size once. With Ollama's default
of 4096 tokens, tool results overflow the context, Ollama silently drops the
oldest messages, and the agents loop and return empty answers.

```powershell
ollama pull qwen3.5:9b
[Environment]::SetEnvironmentVariable('OLLAMA_CONTEXT_LENGTH', '32768', 'User')
```

Then quit Ollama from the system tray and start it again. Once a model is
loaded, `ollama ps` shows the context in use (`CONTEXT` column).

Check that the model answers and makes tool calls:

```powershell
python scripts/check_llm.py                   # the model in .env
python scripts/check_llm.py --model qwen3:8b  # try another model
```

It prints PASS or FAIL for each check and exits with 0 only if both pass.

### 4. MITRE ATT&CK dataset

The normalizer checks technique IDs against MITRE's Enterprise ATT&CK
dataset (pinned version, about 55 MB, saved to `data/reference/attack/`,
gitignored). The pipeline never downloads it and stops with a clear error if
it is missing.

```powershell
python scripts/fetch_attack.py
```

### 5. Load the data

```powershell
python ingest.py                     # loads data/exports into data/report.db
python ingest.py data/exports_bad    # the broken delivery: must be rejected
```

Each file is reported as `LOADED`, `SKIPPED` (identical file already loaded)
or `REJECTED` with its errors. A file with any error loads nothing, and a
second file for a product and year that is already loaded is rejected.
Rejections are also appended to `ingest_errors.log`. Exit code: 0 nothing
rejected, 1 a file was rejected, 2 usage or reference-data error.

To see what the agents' queries return:

```powershell
python report_tools.py               # a demo of every query for 2026
```

## Run the pipeline

```powershell
python run_report.py --year 2026
```

The run prints its folder (`runs/<run_id>/`) and then works through the
analysis. It pauses twice for you:

1. **Outline.** You see the thesis, the signature metric, the ranked themes,
   and each section with the statements of its findings, plus the findings
   no section uses and the data gaps.
2. **Report.** You see the executive summary and the list of verified
   sections.

At each pause, answer:

- `a` to approve,
- `r` to reject with a comment: the outline goes back to the synthesizer, or
  the executive summary back to its writer, with your comment,
- `b` to abort.

Each section, and the executive summary, gets up to 4 attempts to pass
verification. Every error goes back to its writer for the next attempt. If a
section still fails, the run stops and lists the failures.

**Exit code:** 0 report written, 1 a section failed verification, 3 aborted, 4
the run stopped on an error (printed, with the details in `error.txt` in the run
folder).

### What verification checks

`verify.py` (plain code) checks every section:

- every number is followed directly by a finding tag, e.g. `12.4% [F-007]`
  (years, ATT&CK IDs and list numbers are not counted as numbers)
- the number matches the finding when its query is re-run, at the precision
  shown
- tags only point to findings assigned to that section
- each recommendation is a bullet with at least one tag
- the same value is quoted the same way in every section

A short LLM check then looks for wording that contradicts the data ("rose"
for a fall, "doubled" for a small change, "the top" for rank 2).

### Outputs

Everything a run produces is in `runs/<run_id>/`, so every sentence can be
traced to its finding and the query behind it:

| File | Contents |
|---|---|
| `report.md` | The report, with finding tags |
| `report_clean.md` | The same report without tags |
| `products.json` | The products the run analysed |
| `analyst_<product>.json` | Each analyst's findings; `_dropped.json` lists findings that failed the code check and why; `_transcript.json` every tool call and result |
| `findings.json`, `normalized.json` | All findings, then with ATT&CK techniques, sector, severity and links |
| `review.json` | Low-confidence ATT&CK mappings and findings, for a human to check |
| `normalizer_corrections.json` | Technique IDs, sectors and severities the code rejected or reset |
| `outline_<n>.json` | Each outline version |
| `section_<id>_attempt<n>.json`, `verify_<id>_attempt<n>.json` | Each draft and its verification result |
| `consistency_<n>.json` | Cross-section consistency checks |
| `approvals.json` | Your decisions and comments |
| `failures.json` | Only if a run failed: which sections and why |
| `checkpoints.db` | LangGraph state, so the approval pauses can resume |

## Evaluation

`eval/` holds the evaluation material: the answer key with the patterns
planted in the dummy data, and the scorer. The agents never see it (rule 8).
It is gitignored and never committed, so that neither coding agents nor
people tuning prompts can see what the agents are tested on. To evaluate,
copy the evaluation kit into `eval/` (`answer_key.md`, `score.py`,
`judge_prompt.md`, `test_score.py`).

Score a finished run against the answer key:

```powershell
python eval/score.py runs/<run_id>            # keyword, value and LLM-judge checks
python eval/score.py runs/<run_id> --no-llm   # keyword and value checks only
python eval/score.py runs/<run_id> --json     # also write score.json to the run folder
```

For each pattern it prints whether the report found it, stated it correctly
and, where one applies, gave its caveat, then a total. Expected values are
computed from the database, not copied from the answer key. The LLM judge is
used only where a pattern needs interpretation; set `EVAL_JUDGE_MODEL` to
judge every run with the same model.

Compare models: run the whole pipeline once per model, approving both pauses
automatically, and print score, run time and verification retries:

```powershell
$env:EVAL_MODELS = "qwen3.5:9b,qwen3:8b"
python scripts/compare_models.py --year 2026
```

The table is also saved to `runs/compare_<timestamp>.json`, and each run's
score to its run folder. Each model takes a full run (an hour or more here).

## Tests

```powershell
pytest
```

The tests never call a real model; model nodes are tested with a scripted
fake model. The scorer's tests are in `eval/`: `pytest eval`.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| Agents repeat the same tool calls, or reply with nothing | Ollama's context is too small. Set `OLLAMA_CONTEXT_LENGTH` (step 3) and restart Ollama. |
| `Request timed out` | A request took over 15 minutes. Check that `LLM_REASONING_EFFORT` is `low` or `none` and `LLM_TEMPERATURE` is unset; try a smaller model. |
| `invalid output after one retry` | The model returned unusable JSON twice. Re-run; if it repeats, try another model with `scripts/check_llm.py`. |
| `MITRE ATT&CK data not found` | Run `python scripts/fetch_attack.py`. |
| `Database not found` | Run `python ingest.py`. |
| `Missing environment variable(s)` | Copy `.env.example` to `.env` (step 2). |

## Project layout

```
docs/SPEC.md          design
data/                 product deliveries and reference data (do not edit)
ingest.py             validation and loading
report_tools.py       read-only queries used by the agents
verify.py             number and tag checks
text_numbers.py       finding and matching numbers in text
run_report.py         command-line entry point
agents/               graph, state, model client, tools, nodes, prompts
scripts/              check_llm.py, fetch_attack.py, compare_models.py
eval/                 evaluation only: answer key, scorer (score.py) and its tests
tests/
```
