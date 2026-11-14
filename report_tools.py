"""Read-only query functions for the agents (docs/SPEC.md section 6).

Every function opens the database read-only and returns

    {"value": ..., "source": {"function": "<name>", "params": {...}}, "caveats": [...]}

`params` holds every parameter actually used, defaults included, so a result
can be re-run exactly. Percentages are rounded half-up to 1 decimal (see
`round_half_up`), and are None when dividing by zero.

Ranked results have the shape {"total": ..., "rows": [...]}, where each row has
`rank`, `volume`, `share_pct` (share of the total across every item, not just
the rows shown), `previous_volume`, `pct_change`, `previous_rank` and
`new_this_year`. Ties share a rank (1, 2, 2, 4) and are listed alphabetically.
Items with zero volume are not ranked.

Run `python report_tools.py` for a demo of every function for 2026.
Standard library only.
"""

import json
import sqlite3
import statistics
import sys
from contextlib import contextmanager
from decimal import ROUND_HALF_UP, Decimal

from ingest import ATTACK_TYPES, db_path

SEVERITY_ORDER = ["low", "medium", "high", "critical"]

CAVEAT_CROSS_PRODUCT = (
    "Summed across products. One attack can be seen by more than one product "
    "(e.g. email gateway and EDR), so this may overcount attacks."
)
CAVEAT_GEOLOCATION = (
    "Based on IP geolocation of the attacking infrastructure, not attribution of "
    "the attacker. VPNs, proxies and compromised hosts are common."
)
CAVEAT_UNMAPPED = (
    "Some vendor malware names have no common family mapping; see unmapped_malware()."
)
CAVEAT_BLOCKED_ONLY = (
    "This product reports only blocked events, so a block rate cannot be calculated."
)


# --- rounding ---------------------------------------------------------------------------

def round_half_up(x, places: int = 1) -> float | None:
    """Round half away from zero (12.25 -> 12.3), unlike Python's round()."""
    if x is None:
        return None
    q = Decimal(1).scaleb(-places)
    return float(Decimal(str(x)).quantize(q, rounding=ROUND_HALF_UP))


def pct(numerator, denominator) -> float | None:
    """numerator / denominator * 100, rounded to 1 decimal; None if denominator is 0."""
    if not denominator:
        return None
    exact = Decimal(numerator) * 100 / Decimal(denominator)
    return float(exact.quantize(Decimal("0.1"), rounding=ROUND_HALF_UP))


# --- connection and shared helpers ---------------------------------------------------------

@contextmanager
def _connect():
    """Open the database read-only (mode=ro) and close it afterwards."""
    path = db_path()
    if not path.is_file():
        raise FileNotFoundError(f"Database not found at {path}. Run `python ingest.py` first.")
    conn = sqlite3.connect(f"{path.as_uri()}?mode=ro", uri=True)
    try:
        yield conn
    finally:
        conn.close()


def _result(function: str, params: dict, value, *caveat_lists) -> dict:
    caveats: list[str] = []
    for lst in caveat_lists:
        for c in lst:
            if c not in caveats:
                caveats.append(c)
    return {"value": value, "source": {"function": function, "params": params}, "caveats": caveats}


def _check_year(year) -> None:
    if not isinstance(year, int) or isinstance(year, bool):
        raise ValueError(f"year must be an integer, got {year!r}")


def _check_product(conn, product) -> None:
    if product is None:
        return
    known = [r[0] for r in conn.execute("SELECT product FROM products ORDER BY product")]
    if product not in known:
        raise ValueError(f"unknown product {product!r}; valid products: {', '.join(known)}")


def _check_attack_type(attack_type) -> None:
    if attack_type is not None and attack_type not in ATTACK_TYPES:
        raise ValueError(
            f"unknown attack_type {attack_type!r}; valid values: {', '.join(sorted(ATTACK_TYPES))}"
        )


def _where(year, product=None, attack_type=None, action=None) -> tuple[str, list]:
    clauses, params = ["e.year = ?"], [year]
    for column, value in (("product", product), ("attack_type", attack_type), ("action", action)):
        if value is not None:
            clauses.append(f"e.{column} = ?")
            params.append(value)
    return " AND ".join(clauses), params


def _sum(conn, year, product=None, attack_type=None, action=None) -> int:
    where, params = _where(year, product, attack_type, action)
    return conn.execute(f"SELECT COALESCE(SUM(e.count), 0) FROM events_monthly e WHERE {where}",
                        params).fetchone()[0]


def _loaded(conn) -> dict[str, set[int]]:
    loaded: dict[str, set[int]] = {}
    for product, year in conn.execute("SELECT product, year FROM load_log"):
        loaded.setdefault(product, set()).add(year)
    return loaded


def _cross_product(product) -> list[str]:
    return [CAVEAT_CROSS_PRODUCT] if product is None else []


def _current_coverage(conn, year, product) -> list[str]:
    """Caveat when no data is loaded for the requested year."""
    loaded = _loaded(conn)
    if product is not None:
        return [] if year in loaded.get(product, set()) else [f"No data is loaded for {product} in {year}."]
    registry = [r[0] for r in conn.execute("SELECT product FROM products ORDER BY product")]
    missing = [p for p in registry if year not in loaded.get(p, set())]
    return [f"No data is loaded for {year} from: {', '.join(missing)}."] if missing else []


def _previous_coverage(conn, year, product=None, attack_type=None) -> tuple[bool, list[str]]:
    """Is previous-year data available for this scope? Returns (available, caveats).

    The scope is the given product, or every product with matching rows in
    either year. If none of them has previous-year data, the comparison is not
    possible. If only some lack it, the comparison is made and a caveat names them.
    """
    prev = year - 1
    no_prev = f"No data is loaded for {prev}, so no year-over-year comparison is possible."
    loaded = _loaded(conn)
    if product is not None:
        return (True, []) if prev in loaded.get(product, set()) else (False, [no_prev])

    clauses, params = ["year IN (?, ?)"], [year, prev]
    if attack_type is not None:
        clauses.append("attack_type = ?")
        params.append(attack_type)
    relevant = [r[0] for r in conn.execute(
        f"SELECT DISTINCT product FROM events_monthly WHERE {' AND '.join(clauses)} ORDER BY product", params)]
    if not relevant:
        available = any(prev in years for years in loaded.values())
        return (True, []) if available else (False, [no_prev])
    missing = [p for p in relevant if prev not in loaded.get(p, set())]
    if len(missing) == len(relevant):
        return False, [no_prev]
    if missing:
        return True, [f"No data is loaded for {prev} from {', '.join(missing)}, "
                      "so previous-year values exclude it."]
    return True, []


def _competition_ranks(volumes: dict[str, int]) -> dict[str, int]:
    """Rank by volume descending; ties share a rank (1, 2, 2, 4)."""
    ranks, rank, last = {}, 0, None
    for position, (name, volume) in enumerate(sorted(volumes.items(), key=lambda kv: (-kv[1], kv[0])), 1):
        if volume != last:
            rank, last = position, volume
        ranks[name] = rank
    return ranks


def _volumes(conn, key_expr, year, product, joins="", extra="") -> dict[str, int]:
    where, params = _where(year, product)
    sql = (f"SELECT {key_expr} AS k, SUM(e.count) AS v FROM events_monthly e {joins} "
           f"WHERE {where} {extra} GROUP BY k HAVING v > 0")
    return dict(conn.execute(sql, params).fetchall())


def _ranked(conn, field, key_expr, year, product, n=None, joins="", extra="") -> tuple[dict, list[str]]:
    current = _volumes(conn, key_expr, year, product, joins, extra)
    available, caveats = _previous_coverage(conn, year, product)
    previous = _volumes(conn, key_expr, year - 1, product, joins, extra) if available else {}
    ranks, prev_ranks = _competition_ranks(current), _competition_ranks(previous)
    total = sum(current.values())

    rows = []
    for name in sorted(current, key=lambda k: (ranks[k], k)):
        volume = current[name]
        prev_volume = previous.get(name, 0) if available else None
        rows.append({
            "rank": ranks[name],
            field: name,
            "volume": volume,
            "share_pct": pct(volume, total),
            "previous_volume": prev_volume,
            "pct_change": pct(volume - prev_volume, prev_volume) if available else None,
            "previous_rank": prev_ranks.get(name) if available else None,
            "new_this_year": (name not in previous) if available else None,
        })
    return {"total": total, "rows": rows[:n] if n is not None else rows}, caveats


def _compare(conn, year, product=None, attack_type=None) -> tuple[dict, list[str]]:
    current = _sum(conn, year, product, attack_type, "blocked")
    available, caveats = _previous_coverage(conn, year, product, attack_type)
    if not available:
        return {"current": current, "previous": None, "change": None, "pct_change": None}, caveats
    previous = _sum(conn, year - 1, product, attack_type, "blocked")
    change = current - previous
    return {"current": current, "previous": previous, "change": change,
            "pct_change": pct(change, previous)}, caveats


# --- query functions ----------------------------------------------------------------------

def list_products() -> dict:
    """Registry rows plus the attack types each product reports and the years loaded."""
    with _connect() as conn:
        loaded = _loaded(conn)
        types: dict[str, list[str]] = {}
        for product, attack_type in conn.execute(
                "SELECT DISTINCT product, attack_type FROM events_monthly ORDER BY product, attack_type"):
            types.setdefault(product, []).append(attack_type)
        rows = [
            {"product": p, "category": c, "owner": o, "description": d,
             "attack_types": types.get(p, []), "years_loaded": sorted(loaded.get(p, set()))}
            for p, c, o, d in conn.execute(
                "SELECT product, category, owner, description FROM products ORDER BY product")
        ]
    return _result("list_products", {}, rows)


def attacks_blocked(year: int, product: str | None = None, attack_type: str | None = None) -> dict:
    """Sum of count where action = 'blocked'."""
    _check_year(year)
    _check_attack_type(attack_type)
    with _connect() as conn:
        _check_product(conn, product)
        value = _sum(conn, year, product, attack_type, "blocked")
        coverage = _current_coverage(conn, year, product)
    params = {"year": year, "product": product, "attack_type": attack_type}
    return _result("attacks_blocked", params, value, _cross_product(product), coverage)


def compare_years(year: int, product: str | None = None, attack_type: str | None = None) -> dict:
    """Blocked attacks this year vs. the previous year: current, previous, change, pct_change."""
    _check_year(year)
    _check_attack_type(attack_type)
    with _connect() as conn:
        _check_product(conn, product)
        value, prev_caveats = _compare(conn, year, product, attack_type)
        coverage = _current_coverage(conn, year, product)
    params = {"year": year, "product": product, "attack_type": attack_type}
    return _result("compare_years", params, value, _cross_product(product), coverage, prev_caveats)


def product_summary(year: int, product: str) -> dict:
    """Per attack type: blocked, detected_only, block_rate_pct, yoy_blocked, by_severity.

    Covers every attack type the product reported this year or last year.
    """
    _check_year(year)
    if product is None:
        raise ValueError("product is required")
    with _connect() as conn:
        _check_product(conn, product)
        caveats = _current_coverage(conn, year, product)
        blocked_only = conn.execute(
            "SELECT 1 FROM events_monthly WHERE product = ? AND year = ? AND action = 'detected_only' LIMIT 1",
            (product, year)).fetchone() is None
        if blocked_only:
            caveats.append(CAVEAT_BLOCKED_ONLY)
        attack_types = [r[0] for r in conn.execute(
            "SELECT DISTINCT attack_type FROM events_monthly WHERE product = ? AND year IN (?, ?) "
            "ORDER BY attack_type", (product, year, year - 1))]
        value = {}
        for at in attack_types:
            blocked = _sum(conn, year, product, at, "blocked")
            detected = _sum(conn, year, product, at, "detected_only")
            yoy, yoy_caveats = _compare(conn, year, product, at)
            caveats += yoy_caveats
            severity = dict(conn.execute(
                "SELECT severity, SUM(count) FROM events_monthly WHERE product = ? AND year = ? "
                "AND attack_type = ? GROUP BY severity", (product, year, at)).fetchall())
            value[at] = {
                "blocked": blocked,
                "detected_only": detected,
                "block_rate_pct": None if blocked_only else pct(blocked, blocked + detected),
                "yoy_blocked": yoy,
                "by_severity": {s: severity.get(s, 0) for s in SEVERITY_ORDER},
            }
    return _result("product_summary", {"year": year, "product": product}, value, caveats)


def attack_type_changes(year: int, product: str | None = None) -> dict:
    """compare_years for every attack type, ranked from largest rise to largest fall.

    Attack types whose pct_change is None are listed last, with rank None.
    """
    _check_year(year)
    with _connect() as conn:
        _check_product(conn, product)
        where, params = _where(year, product)
        where = where.replace("e.year = ?", "e.year IN (?, ?)")
        params = [year, year - 1] + params[1:]
        attack_types = [r[0] for r in conn.execute(
            f"SELECT DISTINCT e.attack_type FROM events_monthly e WHERE {where} ORDER BY 1", params)]
        caveats, rows = _current_coverage(conn, year, product), []
        for at in attack_types:
            value, c = _compare(conn, year, product, at)
            caveats += c
            rows.append({"attack_type": at, **value})
    rows.sort(key=lambda r: (r["pct_change"] is None, -(r["pct_change"] or 0), r["attack_type"]))
    ranks = _competition_ranks({r["attack_type"]: r["pct_change"] for r in rows if r["pct_change"] is not None})
    rows = [{"rank": ranks.get(r["attack_type"]), **r} for r in rows]
    return _result("attack_type_changes", {"year": year, "product": product},
                   {"rows": rows}, _cross_product(product), caveats)


def top_malware(year: int, n: int = 10, product: str | None = None) -> dict:
    """Malware families ranked by detections (all actions), using canonical_family.

    Names with no mapping appear as UNMAPPED:<vendor name>.
    """
    _check_year(year)
    _check_n(n)
    with _connect() as conn:
        _check_product(conn, product)
        value, caveats = _ranked(
            conn, "family", "COALESCE(a.canonical_family, 'UNMAPPED:' || e.malware_name)", year, product, n,
            joins="LEFT JOIN malware_aliases a ON a.product = e.product AND a.alias = e.malware_name",
            extra="AND e.malware_name IS NOT NULL")
        unmapped = _unmapped(conn, year, product)
        coverage = _current_coverage(conn, year, product)
    params = {"year": year, "n": n, "product": product}
    return _result("top_malware", params, value, _cross_product(product), coverage, caveats,
                   [CAVEAT_UNMAPPED] if unmapped else [])


def _unmapped(conn, year, product) -> list[dict]:
    where, params = _where(year, product)
    sql = (f"SELECT e.product, e.malware_name, SUM(e.count) AS v FROM events_monthly e "
           f"LEFT JOIN malware_aliases a ON a.product = e.product AND a.alias = e.malware_name "
           f"WHERE {where} AND e.malware_name IS NOT NULL AND a.alias IS NULL "
           f"GROUP BY e.product, e.malware_name ORDER BY v DESC, e.product, e.malware_name")
    return [{"product": p, "vendor_name": m, "detections": v} for p, m, v in conn.execute(sql, params)]


def unmapped_malware(year: int, product: str | None = None) -> dict:
    """Product, vendor name and detections for every malware name with no family mapping."""
    _check_year(year)
    with _connect() as conn:
        _check_product(conn, product)
        rows = _unmapped(conn, year, product)
        coverage = _current_coverage(conn, year, product)
    return _result("unmapped_malware", {"year": year, "product": product}, {"rows": rows}, coverage)


def top_countries(year: int, n: int = 10, product: str | None = None) -> dict:
    """Source countries ranked by attack volume (all actions)."""
    _check_year(year)
    _check_n(n)
    with _connect() as conn:
        _check_product(conn, product)
        value, caveats = _ranked(conn, "country", "e.source_country", year, product, n)
        coverage = _current_coverage(conn, year, product)
    params = {"year": year, "n": n, "product": product}
    return _result("top_countries", params, value, [CAVEAT_GEOLOCATION], _cross_product(product),
                   coverage, caveats)


def sector_breakdown(year: int, product: str | None = None) -> dict:
    """Attack volume by client sector (all actions), ranked."""
    _check_year(year)
    with _connect() as conn:
        _check_product(conn, product)
        value, caveats = _ranked(conn, "sector", "e.client_sector", year, product)
        coverage = _current_coverage(conn, year, product)
    return _result("sector_breakdown", {"year": year, "product": product}, value,
                   _cross_product(product), coverage, caveats)


def severity_breakdown(year: int, product: str | None = None) -> dict:
    """Attack volume by severity (all actions), ranked."""
    _check_year(year)
    with _connect() as conn:
        _check_product(conn, product)
        value, caveats = _ranked(conn, "severity", "e.severity", year, product)
        coverage = _current_coverage(conn, year, product)
    return _result("severity_breakdown", {"year": year, "product": product}, value,
                   _cross_product(product), coverage, caveats)


def monthly_series(year: int, product: str | None = None, attack_type: str | None = None,
                   spike_factor: float = 1.5) -> dict:
    """Blocked count per month, with month-on-month change, same month last year,
    peak and low month (earliest on ties), median, and spike months (blocked at
    least spike_factor times the median)."""
    _check_year(year)
    _check_attack_type(attack_type)
    if not isinstance(spike_factor, (int, float)) or isinstance(spike_factor, bool) or spike_factor <= 0:
        raise ValueError(f"spike_factor must be a positive number, got {spike_factor!r}")
    with _connect() as conn:
        _check_product(conn, product)
        caveats = _current_coverage(conn, year, product)
        available, prev_caveats = _previous_coverage(conn, year, product, attack_type)

        def per_month(y):
            where, params = _where(y, product, attack_type, "blocked")
            return dict(conn.execute(
                f"SELECT e.month, SUM(e.count) FROM events_monthly e WHERE {where} GROUP BY e.month",
                params).fetchall())

        current = per_month(year)
        previous = per_month(year - 1) if available else {}

        # Months with no rows at all from a loaded product are a data gap (rule 5).
        loaded = _loaded(conn)
        scope = [product] if product else sorted(p for p, ys in loaded.items() if year in ys)
        for p in scope:
            if year not in loaded.get(p, set()):
                continue
            present = {r[0] for r in conn.execute(
                "SELECT DISTINCT month FROM events_monthly WHERE product = ? AND year = ?", (p, year))}
            missing = [f"{year}-{m:02d}" for m in range(1, 13) if f"{year}-{m:02d}" not in present]
            if missing:
                caveats.append(f"{p} has no rows for {', '.join(missing)}; these months are a data gap.")

    months, before = [], None
    for m in range(1, 13):
        key = f"{year}-{m:02d}"
        blocked = current.get(key, 0)
        months.append({
            "month": key,
            "blocked": blocked,
            "mom_change": None if before is None else blocked - before,
            "mom_pct_change": None if before is None else pct(blocked - before, before),
            "previous_year_blocked": previous.get(f"{year - 1}-{m:02d}", 0) if available else None,
        })
        before = blocked

    values = [x["blocked"] for x in months]
    median = statistics.median(values)
    if median > 0:
        threshold = Decimal(str(spike_factor)) * Decimal(str(median))
        spikes = [x["month"] for x in months if Decimal(x["blocked"]) >= threshold]
    else:
        spikes = []
        caveats.append("The monthly median is 0, so spike months cannot be identified.")
    total = sum(values)
    value = {
        "months": months,
        "total": total,
        "peak_month": None if total == 0 else min(months, key=lambda x: -x["blocked"])["month"],
        "low_month": None if total == 0 else min(months, key=lambda x: x["blocked"])["month"],
        "median": round_half_up(median),
        "spike_factor": spike_factor,
        "spike_months": spikes,
    }
    params = {"year": year, "product": product, "attack_type": attack_type, "spike_factor": spike_factor}
    return _result("monthly_series", params, value, _cross_product(product), caveats, prev_caveats)


def _check_n(n) -> None:
    if not isinstance(n, int) or isinstance(n, bool) or n < 1:
        raise ValueError(f"n must be a positive integer, got {n!r}")


TOOLS = [
    list_products,
    attacks_blocked,
    compare_years,
    product_summary,
    attack_type_changes,
    top_malware,
    unmapped_malware,
    top_countries,
    monthly_series,
    sector_breakdown,
    severity_breakdown,
]


# --- demo ------------------------------------------------------------------------------------

def _print_result(call: str, result: dict) -> None:
    print(f"\n=== {call}")
    print(f"source:  {json.dumps(result['source'])}")
    for c in result["caveats"]:
        print(f"caveat:  {c}")
    value = result["value"]
    if isinstance(value, dict) and any(isinstance(v, list) and v and isinstance(v[0], dict)
                                       for v in value.values()):
        for k, v in value.items():
            if isinstance(v, list) and v and isinstance(v[0], dict):
                print(f"{k}:")
                for row in v:
                    print(f"  {json.dumps(row)}")
            else:
                print(f"{k}: {json.dumps(v)}")
    elif isinstance(value, dict):
        print("value:")
        for k, v in value.items():
            print(f"  {k}: {json.dumps(v)}")
    elif isinstance(value, list):
        print("value:")
        for row in value:
            print(f"  {json.dumps(row)}")
    else:
        print(f"value:   {json.dumps(value)}")


def demo(year: int = 2026) -> None:
    products = list_products()
    _print_result("list_products()", products)
    first = products["value"][0]["product"] if products["value"] else None
    _print_result(f"attacks_blocked({year})", attacks_blocked(year))
    _print_result(f"compare_years({year})", compare_years(year))
    for p in products["value"]:
        _print_result(f"product_summary({year}, {p['product']!r})", product_summary(year, p["product"]))
    _print_result(f"attack_type_changes({year})", attack_type_changes(year))
    _print_result(f"top_malware({year})", top_malware(year))
    _print_result(f"unmapped_malware({year})", unmapped_malware(year))
    _print_result(f"top_countries({year})", top_countries(year))
    _print_result(f"monthly_series({year})", monthly_series(year))
    if first:
        _print_result(f"monthly_series({year}, {first!r})", monthly_series(year, first))
    _print_result(f"sector_breakdown({year})", sector_breakdown(year))
    _print_result(f"severity_breakdown({year})", severity_breakdown(year))


if __name__ == "__main__":
    try:
        demo()
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}")
        sys.exit(1)
