# Yearly security report: multi-agent PoC

## What this project is

A system that generates a yearly report on our security products: product
performance (attacks blocked), top malware families, attack source countries,
and trends. A pipeline of agents reads aggregated data from a database and
writes the report. This is a proof of concept running on dummy data.

The full design is in `docs/SPEC.md`. Read it before starting any step, and
follow it. If the spec and a request seem to conflict, ask.

## Architecture

```
data/exports/*.csv -> ingest.py (validation, no AI) -> data/report.db (SQLite)
  -> agents (read-only, through report_tools.py only):
     product analysts (one per product) + cross-product analyst, in parallel
       -> normalizer -> synthesizer -> [human approves outline]
       -> section writers (parallel) -> verifier (retry loop, max 4 attempts)
       -> executive summary -> verifier -> [human approves] -> report
```

## Hard rules

These are design requirements, not preferences. Do not work around them. If a
task seems to require breaking one, stop and ask.

1. **LLMs never compute numbers.** Every value, sum, percentage, rank, and
   year-over-year change comes from a `report_tools.py` function or other plain
   Python code. Prompts must tell agents to copy values from tool results, never
   to calculate.
2. **Agents access data only through `report_tools.py` functions.** No SQL in
   agent code, no direct database connections from nodes.
3. **Section writers and the executive summary agent get no tools.** They work
   only from the findings passed to them in state.
4. **Every number in the report is tagged with its finding ID**, like
   `the metric rose 12.4% [F-007]`. `verify.py` checks every tagged number against
   the finding's source and flags any untagged number (years like 2026 are allowed).
5. **Missing or unmapped data is reported as a data gap**, never guessed or dropped.
6. **Caveats in tool results must reach the report.** If a result has caveats,
   the finding keeps them and the relevant section states them.
7. **Open source only, at runtime.** The model is reached through an
   OpenAI-compatible endpoint configured by environment variables (Ollama for
   the PoC, vLLM later). No calls to commercial AI APIs or external services
   while the pipeline runs. All dependencies must have open-source licenses.
8. **Prompts must be general, and `eval/` is off-limits.** Agent prompts describe
   how to analyze and write, never what the data contains: no specific malware
   families, countries, percentages, months, or trends from `data/`. The
   evaluation material in `eval/` reveals the patterns the agents are tested on.
   Don't read it, and don't use its contents anywhere, unless the current step
   explicitly says it is the evaluation step.
9. **Don't edit files in `data/`.** They are the product teams' deliveries.
   The ingestion pipeline must handle them as they are, including rejecting
   the broken file in `data/exports_bad/`.
10. **Real data never goes in this repository.**

## Stack

- Python 3.11+
- LangGraph for the agent graph; LangChain's OpenAI-compatible chat client for the model
- Pydantic for all data passed between nodes
- pytest for tests
- Standard library only for the data layer (`ingest.py`, `report_tools.py`)
- Pin versions in `requirements.txt`

Model configuration (environment variables, see `.env.example`):

```
LLM_BASE_URL=http://localhost:11434/v1   # Ollama; vLLM later
LLM_MODEL=<model name>
LLM_API_KEY=not-needed                    # placeholder, Ollama ignores it
```

## Repository layout

```
CLAUDE.md  README.md
docs/SPEC.md                # the design; source of truth
data/                       # provided; do not edit (rule 9)
  exports/                  # one CSV per product per year
  exports_bad/              # a broken delivery that ingestion must reject
  reference/                # products.csv, malware_aliases.csv
  report.db                 # created by ingest.py (gitignored)
ingest.py                   # validation and loading, no AI
report_tools.py             # read-only query functions for the agents
agents/
  state.py                  # graph state and Pydantic schemas
  llm.py                    # model client built from env vars
  tools.py                  # report_tools functions wrapped as LangGraph tools
  graph.py                  # graph definition
  nodes/                    # one module per node
  prompts/                  # one system prompt file per agent (.md)
verify.py                   # deterministic number and tag checks
run_report.py               # CLI entry point
runs/<run_id>/              # outputs of each run (gitignored)
scripts/                    # helper scripts
eval/                       # evaluation only (rule 8)
tests/
```

## Conventions

- Prompts live in `agents/prompts/*.md`, never inline in Python.
- Each node is a function in its own module and is testable without the graph.
- Each run gets an ID (timestamp-based). Every node writes its output to the run
  folder, so any sentence can be traced to its finding and source query.
- LLM output is structured JSON validated by Pydantic. Retry once on invalid
  JSON, then fail with a clear error.
- Write tests for every code-only part: ingestion, query functions, tools
  wrapper, `verify.py`, schemas, graph routing. LLM nodes get smoke tests with
  a fake model.

## Commands

```bash
python ingest.py                         # load data/exports into data/report.db
python ingest.py data/exports_bad        # must reject the broken file
python run_report.py --year 2026         # run the pipeline
pytest
```

## Working style

- Work in small steps. Show me the plan before writing a large change.
- After each step, run the tests and tell me what passed and what didn't.
- Don't add features or files beyond what the current step asks for.
- Keep `README.md` up to date with how to set up and run the project.
