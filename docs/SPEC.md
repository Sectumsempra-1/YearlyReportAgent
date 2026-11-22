# Specification: yearly security report PoC

This is the source of truth for what to build. `CLAUDE.md` has the hard rules;
this document has the details.

## 1. The report

A yearly report on our security products, written for technical managers and
clients. It covers four goals:

- **Product performance:** how many attacks our products blocked for clients,
  per product and per attack type, with year-over-year change
- **Top malware:** the most detected malware families, ranking changes, and
  families new this year
- **Source countries:** where attack traffic comes from, by IP geolocation
- **Trends:** monthly patterns, rising and falling attack types, targeted sectors

Sections, in order:

1. Executive summary
2. Product performance
3. Top malware
4. Source countries
5. Trends
6. Recommendations
7. Methodology and data gaps

The PoC reports on 2026 (current year) compared with 2025 (previous year).

## 2. Data deliveries (`data/exports/`)

Each product team delivers one CSV per year: `<product>_<year>.csv`. These are
monthly aggregated counts, not raw logs, and contain no client names.

| Column | Type | Allowed values / format |
|---|---|---|
| `product` | text | Must exist in `data/reference/products.csv` |
| `month` | text | `YYYY-MM`, month 01–12 |
| `attack_type` | text | `intrusion_attempt`, `brute_force`, `malware_download`, `c2_traffic`, `phishing`, `malware_attachment`, `bec`, `malware_execution`, `ransomware`, `credential_theft` |
| `action` | text | `blocked`, `detected_only` |
| `malware_name` | text | Vendor's malware name; may be empty |
| `source_country` | text | Two-letter ISO 3166 code, uppercase |
| `client_sector` | text | `Energy`, `Finance`, `Government`, `Manufacturing`, `Healthcare`, `Telecom` |
| `severity` | text | `low`, `medium`, `high`, `critical` |
| `count` | integer | Whole number ≥ 0 |

The header must be exactly these columns in this order. A file contains exactly
one product and one year.

`data/exports_bad/` holds a broken delivery. Ingestion must reject it.

## 3. Reference data (`data/reference/`)

- `products.csv`: `product, category, owner, description`. The product registry.
- `malware_aliases.csv`: `product, alias, canonical_family`. Each product names
  malware differently; this maps a product's vendor name to one common family
  name. It may be incomplete. Unmapped names are a data gap to report, not an
  error to fix by guessing.

## 4. Ingestion (`ingest.py`)

Plain Python, standard library only, no AI.

- Usage: `python ingest.py [folder ...]`, default `data/exports`. Always loads
  the reference data first (upsert).
- Validate every row against section 2. Collect all errors for a file, each
  with its line number and a clear message, such as
  `line 3: invalid month '2026-13' (expected YYYY-MM)`.
- **A file with any error is rejected as a whole.** Nothing from it is loaded.
- A file whose SHA-256 matches an already loaded file is skipped.
- A file for a product and year that is already loaded is rejected, so data is
  never counted twice.
- Each accepted file loads in one transaction and gets a `load_log` row.
- Print one status line per file (`LOADED`, `SKIPPED`, `REJECTED`) with up to
  10 messages, and append rejections with all their errors to `ingest_errors.log`.

*Added 2026-11-12 (see section 12):*

- `source_country` is checked against an ISO 3166-1 alpha-2 list embedded in
  the code, not only its format.
- Two rows with the same values in every column except `count` are an error.
- A file with only a header (no data rows) is rejected. A UTF-8 BOM is accepted.
- The file name is not checked; the file's contents decide product and year.
- Order: row validation first, then the duplicate product/year check. All
  errors found are reported together.
- `ingest_errors.log` lives in the project root and is gitignored.

## 5. Database (`data/report.db`, SQLite)

| Table | Columns |
|---|---|
| `products` | `product` (PK), `category`, `owner`, `description` |
| `malware_aliases` | `product`, `alias`, `canonical_family`; PK (`product`, `alias`) |
| `load_log` | `load_id` (PK), `file`, `sha256` (unique), `product`, `year`, `rows`, `loaded_at` (UTC ISO) |
| `events_monthly` | `id` (PK), `load_id` (FK), `product`, `year`, `month`, `attack_type`, `action`, `malware_name` (NULL if empty), `source_country`, `client_sector`, `severity`, `count` |

Index `events_monthly` on (`year`, `product`, `attack_type`).

## 6. Query functions (`report_tools.py`)

Standard library only. Every function opens the database **read-only**
(`file:data/report.db?mode=ro`) and returns:

```python
{"value": ..., "source": {"function": "<name>", "params": {...}}, "caveats": [...]}
```

Export the list of functions as `TOOLS`. Running the module directly prints a
demo of every function for 2026.

| Function | Returns |
|---|---|
| `list_products()` | Registry rows plus the attack types each product reports |
| `attacks_blocked(year, product=None, attack_type=None)` | Sum of `count` where `action = 'blocked'` |
| `compare_years(year, product=None, attack_type=None)` | `current`, `previous`, `change`, `pct_change` (1 decimal; None if previous is 0) for `attacks_blocked` |
| `product_summary(year, product)` | Per attack type: `blocked`, `detected_only`, `block_rate_pct`, and `yoy_blocked` (the `compare_years` value) |
| `top_malware(year, n=10)` | Families ranked by detections (all actions), using `canonical_family`; names with no mapping appear as `UNMAPPED:<vendor name>` |
| `unmapped_malware(year)` | Product, vendor name, detections for every name with no mapping |
| `top_countries(year, n=10)` | Countries ranked by attack volume (all actions) |
| `monthly_series(year, product=None, attack_type=None)` | Blocked count per month |
| `sector_breakdown(year)` | Attack volume by sector (all actions), ranked |

Ranked results include `rank`, `share_pct` (1 decimal, share of the full list),
and for `top_malware` and `top_countries` also `previous_rank` (None if absent
last year) and `new_this_year`.

Caveats to attach:

- When summing across products (any function not limited to one product):
  *"Summed across products. One attack can be seen by more than one product
  (e.g. email gateway and EDR), so this may overcount attacks."*
- `top_countries`: *"Based on IP geolocation of the attacking infrastructure,
  not attribution of the attacker. VPNs, proxies and compromised hosts are common."*
- `top_malware`, when any `UNMAPPED:` entry is present: *"Some vendor malware
  names have no common family mapping; see unmapped_malware()."*

### 6.1 Additions (2026-11-12, see section 12)

**Database path.** Read from the `REPORT_DB` environment variable, default
`data/report.db` resolved from the project root (not the working directory).

**Product filter.** `top_malware`, `top_countries`, `sector_breakdown` and
`unmapped_malware` take an optional `product=None`. When a product is given,
the "summed across products" caveat is not attached.

**New functions:**

| Function | Returns |
|---|---|
| `severity_breakdown(year, product=None)` | Attack volume by severity (all actions), ranked, with `previous_rank` |
| `attack_type_changes(year, product=None)` | The `compare_years` result for every attack type, ranked from largest rise to largest fall by `pct_change` (attack types with `pct_change` None listed last) |

**Changed return values:**

- `monthly_series`: each month has `blocked`, `mom_change`, `mom_pct_change`
  (vs. previous month; None for January) and `previous_year_blocked` (same
  month last year). The result also has `peak_month`, `low_month`, `median`,
  and `spike_months`: months whose `blocked` is at least `spike_factor` times
  the year's median (`spike_factor` is a parameter, default 1.5).
- `product_summary`: each attack type also has `by_severity` (count per
  severity, all actions). If the product reports no `detected_only` rows at
  all, `block_rate_pct` is None and the result gets the caveat *"This product
  reports only blocked events, so a block rate cannot be calculated."*
- `top_countries` and `sector_breakdown`: each row also has `previous_volume`,
  `pct_change` and `previous_rank`. `sector_breakdown` also has `new_this_year`.
- `compare_years`: if no data is loaded for the previous year, `previous` and
  `pct_change` are None and the result gets the caveat *"No data is loaded for
  <year-1>, so no year-over-year comparison is possible."* This is different
  from a previous value of 0.

**Ranking and rounding:**

- `share_pct` is the share of the total across every item, not just the top n.
- `previous_rank` comes from the previous year's full ranking, not its top n.
- Ties share a rank (1, 2, 2, 4); tied items are listed alphabetically.
- Every percentage is rounded to 1 decimal and is None when dividing by zero.

## 7. Agent layer

LangGraph graph. Shared rules for all LLM nodes: structured output validated by
Pydantic, prompts in `agents/prompts/`, every output saved to the run folder.

### 7.1 Product analyst (one per product, parallel)

- **Input:** one product and the year. The product list comes from `list_products()`.
- **Tools:** the `report_tools` functions.
- **Does:** explores the product's data and decides what is significant this
  year: large changes, new patterns, broken trends, spikes.
- **Output:** a list of `Finding`.
- **Checks in code:** every value in a finding appears in the cited tool result
  at the cited key path. Findings that fail are dropped and logged.
- *Added 2026-11-12:* a product analyst may only cite tool calls with
  `product` set to its own product (or `list_products()`). Findings citing
  other calls are dropped and logged.

### 7.1a Cross-product analyst (added 2026-11-12)

- Runs in parallel with the product analysts. Same tools.
- Owns all calls with `product=None`: totals, top malware, top countries,
  sectors, severity, unmapped names. Its findings have `product = "ALL"`.
- Same checks in code as 7.1, except that it may only cite calls with
  `product=None` (or `list_products()`).

### 7.1b Collecting findings (code, added 2026-11-12)

After all analysts finish, code assigns finding IDs (`F-001`, ...) in a stable
order and sets `direction` from the cited change: `new` if the previous value
is 0 or the item is new this year, `flat` if `pct_change` is between -1.0 and
1.0, otherwise `up` or `down`. Findings without a change have direction `flat`.
Caveats from the cited tool results are copied into the finding by code.

### 7.2 Normalizer

- **Input:** all findings.
- **Does:** maps findings to MITRE ATT&CK techniques; standardizes sector and
  severity; links findings that describe related activity across products
  (links, never merges); gives each mapping a confidence score.
- **Reference:** MITRE's enterprise-attack STIX bundle from the
  `mitre-attack/attack-stix-data` GitHub repository, downloaded by a script.
- **Checks in code:** technique IDs not in the MITRE dataset are rejected.
  Confidence below 0.6 goes to `review.json` in the run folder.
- **Output:** a list of `NormalizedFinding`.
- *Added 2026-11-12:*
  - `sector` and `severity` may only be set to a value that appears in the
    finding's cited tool result. Otherwise `sector` is `"multiple"` or
    `"unspecified"` and `severity` is `"unspecified"`. Code checks this.
  - A finding with low confidence stays in the report; only its technique
    mappings below 0.6 are left out of the report and listed in `review.json`.
  - The MITRE bundle is downloaded by `scripts/download_mitre.py` at a pinned
    ATT&CK version, as a setup step. A run stops with a clear error if the
    file is missing. The pipeline never downloads it.

### 7.3 Synthesizer

- **Input:** all normalized findings.
- **Does:** groups findings into 3–5 themes ranked by importance, writes a
  one-sentence thesis, picks the signature metric, and assigns findings to the
  report sections from section 1.
- **Checks in code:** every finding ID exists; every section except methodology
  has at least one finding.
- **Output:** `Outline`.
- **Then:** the graph pauses for human approval, showing the outline readably.
- *Added 2026-11-12:* the outline's sections are 2–6 from section 1 (written
  by section writers). The executive summary (7.6) and methodology (7.7) are
  not in the outline. Approval is a command-line prompt with three choices:
  approve, reject with a comment (the synthesizer runs again with the comment,
  then asks again), or abort. It uses a LangGraph interrupt with a SQLite
  checkpointer. The final approval in 7.6 works the same way, with rejection
  sending the executive summary back to its writer.

### 7.4 Section writers (one per section, parallel)

- **Input:** one outline section and only its assigned findings. **No tools.**
- **Does:** writes the section in Markdown for a technical but non-specialist
  reader.
- **Rules:** every number is copied from a finding and followed by its tag;
  caveats are stated where they apply; data gaps are stated plainly; every
  recommendation cites at least one finding.
- **Output:** `Section`.

### 7.5 Verifier

Code first, then a small LLM check. See section 9.

- **On failure:** the section goes back to its writer with the error list.
  After 4 failed attempts, the run stops and reports which sections failed.
  *(Clarified 2026-11-12: a wording-check failure counts as a failed attempt.
  Changed 2026-11-14: 4 attempts in total, the first write plus up to 3
  rewrites; was 3.)*

### 7.6 Executive summary

- **Input:** only verified sections and the approved outline. **No tools.**
- **Does:** thesis, 5–8 headline numbers from verified findings, one short
  paragraph per theme, top recommendations. Same tagging rules.
- **Then:** verified like any section, then the graph pauses for final human approval.

### 7.7 Final assembly (code)

Writes `report.md` (with tags) and `report_clean.md` (tags removed) in section
order. The methodology section is generated from the data sources, the tool
caveats, and the data gaps.

*Added 2026-11-12:* numbers in the methodology section are tagged like any
other section and checked by `verify.py` before the report is written.

## 8. Data contracts (Pydantic)

- **Finding:** `id` (`F-001`, ...), `product`, `statement`, `values` (copied from
  tool results), `source` (function, params, and the key path to each value),
  `direction` (`up` / `down` / `flat` / `new`), `caveats`, `data_gap` (bool).
  *(2026-11-12: `product` is `"ALL"` for cross-product findings; `id`,
  `direction` and `caveats` are set by code, see 7.1b.)*
- **NormalizedFinding:** Finding plus `attack_techniques` (validated IDs),
  `sector`, `severity`, `related_findings`, `confidence` (0–1)
- **Outline:** `thesis`, `signature_metric`, `themes`, `sections` (each with `id`,
  `title`, `goal`, `finding_ids`)
- **Section:** `id`, `title`, `markdown`, `finding_ids_used`
- **VerificationResult:** `section_id`, `passed`, `errors` (each with the sentence,
  the problem, and the expected value)

## 9. Verification (`verify.py` plus a wording check)

`verify.py` is plain code, no LLM:

- Find every number in a section and the finding tag after it.
- Re-run the cited finding's source function and compare the number in the
  text with the value at the stored key path, allowing for rounding to the
  precision shown in the text.
- Flag any number without a tag. Years are allowed.
- Flag tags pointing to findings not assigned to that section.
- Flag the same finding quoted with different values in different sections.

The LLM wording check covers only whether words match the data: "doubled"
needs about +100%, "declined" needs a negative change, "the top" needs rank 1.

### 9.1 Detailed rules (added 2026-11-12)

- **What is a number:** any run of digits, optionally with `,` thousands
  separators, a decimal point, a leading sign, or a trailing `%`.
- **Exempt:** years 2000–2099 written alone, digits inside finding tags, and
  ATT&CK technique IDs (`T1234`, `T1234.001`).
- Writers must not write data values as words ("three") or in short forms
  ("1.2M"). Prompts say so.
- **Matching:** a tagged number passes if its absolute value equals the
  absolute value of one of the finding's values, or one of its source
  params (for example the 10 in "top 10"), rounded to the precision shown in
  the text. The direction of a change (rose/fell) is checked by the wording
  check.
- **Conflicting values:** flagged when the same key path of the same finding
  is quoted with different numbers in different sections.
- **Executive summary scope:** it may cite any finding used in a verified
  section.
- **Recommendations:** one Markdown bullet per recommendation; each bullet
  must contain at least one finding tag.

*Added 2026-11-22, when verify.py was built:*

- **Tag position:** the tag must follow the number directly; only spaces or
  a closing bracket may come between them. Numbered-list markers (`1.`) at
  the start of a line are not numbers.
- **Re-run, not stored values:** each number is compared with a fresh re-run
  of the finding's source call, so a stale stored value is caught.
- **Where conflicts are fixed:** sections are verified in parallel, so the
  cross-section check runs once all of them have passed. The earliest
  section in report order is the reference; a later section that quotes the
  same value differently goes back to its writer with the error, and that
  rewrite counts toward its 4 attempts. The executive summary is checked
  against the verified sections in its own verifier.
- **Wording check:** runs only when the code checks pass. It sees each cited
  finding's values, direction and what its values measure, but not the
  finding's statement (so it does not copy the analyst's wording). It runs
  without reasoning and in JSON mode, twice; an issue is kept only if both
  runs report it (same sentence and words), the model marks it as a
  contradiction, and its sentence and contradicting words appear in the
  section. A server error is retried once; a run that still fails is
  skipped. Everything dropped is saved with the reason.

## 10. Runs and traceability

Each run has an ID (timestamp-based) and a folder `runs/<run_id>/` containing
every node's output as JSON, the verification results, the review list, the
approvals, and the final reports. Any sentence in the report can be traced to
its finding, and from the finding to the exact query that produced it.

## 11. Out of scope for the PoC

- Real product data and connections to real products
- Deduplicating attacks across products (the caveat covers it)
- Charts and PDF output
- A web interface
- Replacing or correcting a delivery that is already loaded

## 12. Change log

**2026-11-12**, approved after the first spec review:

- Ingestion: country list, duplicate rows, empty files, BOM, check order (4).
- Query functions: product filters, `severity_breakdown`,
  `attack_type_changes`, monthly peaks and spikes, previous-year values in
  rankings, missing previous year, block rate for blocked-only products,
  ranking and rounding rules, `REPORT_DB` (6.1).
- Agents: cross-product analyst (7.1a), findings collected and IDs assigned
  by code (7.1b), normalizer sector/severity rules and MITRE setup (7.2),
  outline scope and approval flow (7.3), retry count (7.5), methodology
  verified (7.7).
- Verification: number grammar, matching, conflicts, executive summary
  scope, recommendations (9.1).

**2026-11-14:** section writing and verification get 4 attempts in total
(was 3) (7.5).

**2026-11-22:** verification details: tag position, re-run sources,
cross-section conflicts routed back to the later section, wording check
inputs (9.1).

**2026-11-23:** robustness after the first full runs: model calls take
turns (`LLM_MAX_PARALLEL`, default 1); each analyst finding is validated on
its own, so an invalid one is dropped and logged instead of failing the run
(7.1); the wording check ignores an issue whose words only state a direction
that matches the cited findings (9.1).

**2026-11-23:** `eval/` (answer key and scorer) is committed. The answer key
is public, so the score is a practice test: useful to catch regressions, not
proof of quality. A fair score needs new dummy data with a private answer
key (README, Evaluation).
