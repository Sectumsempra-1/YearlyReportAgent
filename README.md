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

> **Status (2026-11-22):** every step is built and runs end to end. The first
> complete run with `qwen3.5:9b` took 2 h 07 min and scored 18 of 24 points
> (75%) against the answer key. See [Handover](#handover) for what works,
> what doesn't yet, and what to do next.

## Requirements

- Python 3.11 or newer (tested on 3.14)
- [Ollama](https://ollama.com) with a model that supports tool calls. The
  default is `qwen3.5:9b`. `python scripts/check_llm.py` tells you whether a
  model works.
- A GPU helps a lot. On an 8 GB GPU (RTX 3060 Ti) a full run takes about
  2 hours with `qwen3.5:9b`.
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
| `LLM_MAX_PARALLEL` | `1` | Requests sent to the server at the same time. Agents still run in parallel, but their model calls take turns. Ollama on one GPU works on one request at a time, and a request waiting in its queue can time out before it starts. Raise this for vLLM. |
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
analysis. **It prints nothing more until the outline is ready, about 30
minutes later**; it is not stuck. To watch progress, look at the files
appearing in the run folder: `analyst_*.json` (within about 25 minutes), then
`normalized.json`, then `outline_1.json`. After the outline,
`section_*_attempt*.json` files appear as sections are written. It pauses
twice for you:

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
people tuning prompts can see what the agents are tested on. A fresh clone
therefore has no `eval/` folder: get the evaluation kit (`answer_key.md`,
`score.py`, `judge_prompt.md`, `test_score.py`) from the project owner
outside git and copy it into `eval/`. Everything else works without it.

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
score to its run folder. Each model takes a full run (about 2 hours here).

## Tests

```powershell
pytest
```

The tests never call a real model; model nodes are tested with a scripted
fake model. The scorer's tests are in `eval/`: `pytest eval`.

## Handover

This section is for whoever takes over the project.

### Where things stand

- Every step in the SPEC is built and the pipeline runs end to end.
- 559 tests pass (540 in `tests/`, 19 in `eval/`). Run them before and after
  every change.
- No wrong number has reached a report: every number goes through
  `verify.py`.
- Model comparison on 2026-11-22 (same data, same scoring, judge
  `qwen3.5:9b`, 8 GB GPU):

  | Model | Result | Score | Time | Rewrites |
  |---|---|---|---|---|
  | `qwen3.5:9b` (run 1) | report written | 18/24 (75%) | 2 h 07 min | 5 |
  | `qwen3.5:9b` (run 2) | report written | 17/24 (71%) | 1 h 36 min | 2 |
  | `granite4.2:8b` | report written | 9/24 (38%) | 1 h 05 min | 12 |
  | `qwen3:8b` | a section failed verification | - | 1 h 22 min | 9 |
  | `gpt-oss:20b` | 2 sections failed verification | - | 19 min | 10 |

  **Use `qwen3.5:9b`.** It is the only model that is both reliable and
  good. `qwen3:8b` failed because of a false alarm in the wording check
  (since fixed: see the SPEC change log, 2026-11-23); it is worth testing
  again. `gpt-oss:20b` is by far the fastest but kept writing numbers
  without their finding tags, even after 4 attempts.

### What the report still misses

The model finds most facts, but often states them one by one instead of
**connecting** them (explaining what causes a change, or which findings
belong together), and it sometimes misses a finding altogether. The details
are in the run's `score.json`. They are deliberately not written here,
because this README is in git and the patterns the agents are tested on
must stay out of it (rule 8).

### Known problems

- **Slow.** About 2 hours per run, because Ollama on one 8 GB GPU answers one
  request at a time and 22% of the model runs on the CPU at a 32k context.
  A bigger GPU or vLLM (`LLM_MAX_PARALLEL` > 1) would help the most.
- **Rewrites.** Sections often need 2 or 3 attempts to pass verification.
  The `verify_<id>_attempt<n>.json` files show why.
- **Duplicate findings.** Analysts sometimes report the same fact twice
  (once per product analyst and once in the cross-product analyst). It does
  no harm, but it clutters the outline.
- **Weak recommendations.** The synthesizer's recommendations are generic.
- **"Blocked" vs "all actions".** Analysts sometimes call a count "blocked"
  when it covers all actions. The wording check does not catch this.
- **ATT&CK mapping.** The normalizer sometimes leaves ransomware findings
  without a technique (they then show up in `review.json`).

### Suggested next steps

1. **Look at `gpt-oss:20b` more closely.** It ran in 19 minutes instead of
   about 2 hours. If its writers can be made to tag every number (a general
   prompt or retry-feedback change, not one aimed at the answer key), it
   would make the project much faster to work on.
2. **Run the same model more than once.** Its answers vary (75% then 71%),
   so one score can be luck. Judge a change by two or three runs, not one.
3. **Speed and reliability:** fewer rewrites, shorter prompts, a faster
   setup. These are safe to work on at any time.
4. **Report quality:** prompt changes must stay general (rule 8). Whoever has
   read `eval/answer_key.md` should not write prompt changes alone: have
   someone else review them, and check that the score improves on the
   patterns the report already found too, not only on the missed ones.

### How to work on it

- Read `CLAUDE.md` (the hard rules) and `docs/SPEC.md` (the design) first.
  When you change behavior, add an entry to the SPEC's change log
  (section 12) and update this README.
- **Prompts** are in `agents/prompts/*.md`. `tests/test_prompts.py` fails if
  a prompt names anything from the data (products, malware, countries,
  months, years, percentages, distinctive numbers). Keep that test passing;
  don't weaken it. `cross_product_analyst.md` must match `analyst.md` from
  section 2 on (a test checks this), so change both together.
- **A new query** goes in `report_tools.py` (standard library only,
  read-only), its docstring describes the result for the model, and it is
  added to `TOOLS`. `agents/tools.py` wraps it automatically.
- **A new node** is a module in `agents/nodes/`, wired in `agents/graph.py`
  (`DEFAULT_NODES`). Give it a stub in `tests/fakes.py` so graph tests stay
  fast.
- **Try one change cheaply** before a full 2-hour run: most nodes can be run
  alone on the files of an earlier run folder (look at their tests for the
  input they need).

### Reading a run

When a run stops or the report looks wrong, the run folder tells you why
(see [Outputs](#outputs)). Start here:

| Question | File |
|---|---|
| Why did the run stop? | `error.txt` (exit code 4) or `failures.json` (exit code 1) |
| What did an analyst look at? | `analyst_<product>_transcript.json` |
| Why is a finding missing? | `analyst_<product>_dropped.json` |
| Why was a section rewritten? | `verify_<id>_attempt<n>.json` |
| Did the wording check ignore a problem? | `wording_dropped_<id>_attempt<n>.json` |
| What did the score count? | `score.json` (only with the evaluation kit) |

### Lessons learned

These cost time once; they are already handled, but don't undo them:

- **Ollama's default context (4096) is too small.** Agents loop and reply
  with nothing. Set `OLLAMA_CONTEXT_LENGTH=32768` (setup step 3).
- **Don't force `LLM_TEMPERATURE=0`** with reasoning models: they repeat
  themselves until they run out of tokens.
- **Keep reasoning effort low.** Full thinking was about 10 times slower
  with no better answers.
- **Keep `LLM_MAX_PARALLEL=1` on Ollama.** Otherwise requests wait in
  Ollama's queue, and the wait counts toward the 15-minute timeout.
- **Small models make small format mistakes**: numbers written as text,
  extra fields, broken JSON. The code fixes harmless ones and drops broken
  findings one at a time (logged in `_dropped.json`), rather than failing
  the run.
- **Windows:** `.gitattributes` keeps `data/` files byte-for-byte (ingestion
  checks file hashes). Downloads use Python, not `curl`, because of
  certificate-check errors.

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `.venv\Scripts\activate` fails: "running scripts is disabled on this system" | Windows blocks PowerShell scripts by default. Run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or skip activation and call `.venv\Scripts\python` directly. |
| `pytest eval` fails: "file or directory not found" | The evaluation kit is not in git; see [Evaluation](#evaluation). |
| Agents repeat the same tool calls, or reply with nothing | Ollama's context is too small. Set `OLLAMA_CONTEXT_LENGTH` (step 3) and restart Ollama. |
| `Request timed out` | A request took over 15 minutes. Keep `LLM_MAX_PARALLEL=1` for Ollama. Check that `LLM_REASONING_EFFORT` is `low` or `none` and `LLM_TEMPERATURE` is unset; try a smaller model. |
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
agents/
  graph.py            the LangGraph graph: fan-out, retry loop, approval pauses
  state.py            Pydantic data contracts between nodes
  llm.py              model client from environment variables
  tools.py            report_tools functions as model tools
  structured.py       JSON parsing with one retry
  finding_check.py    checks each analyst finding against its tool call
  wording.py          the LLM wording check
  attack.py           ATT&CK technique lookup
  nodes/              one module per node
  prompts/            one system prompt per agent
scripts/              check_llm.py, fetch_attack.py, compare_models.py
eval/                 evaluation only, not in git: answer key, scorer and its tests
tests/                one test file per module; fakes.py has the fake model and stub nodes
```
