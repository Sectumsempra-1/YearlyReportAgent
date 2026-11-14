"""Validate product deliveries and load them into SQLite. No AI.

Usage:
    python ingest.py [folder ...]      # default: data/exports

Reference data (data/reference/) is always loaded first (upsert). Then every
*.csv file in each folder is validated against docs/SPEC.md section 2:

- a file with any error is rejected as a whole; nothing from it is loaded
- a file whose SHA-256 matches an already loaded file is skipped
- a file for a product and year that is already loaded is rejected
- each accepted file is loaded in one transaction and gets a load_log row

Prints one status line per file (LOADED, SKIPPED, REJECTED) and appends every
rejection with all its errors to ingest_errors.log. Exits with 1 if any file
was rejected, 2 on a usage or reference-data error, otherwise 0.

The database path comes from REPORT_DB (default data/report.db); relative
paths are resolved from the project root. Standard library only.
"""

import csv
import hashlib
import io
import os
import re
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DB = "data/report.db"
DEFAULT_FOLDER = PROJECT_ROOT / "data" / "exports"
REFERENCE_DIR = PROJECT_ROOT / "data" / "reference"
ERROR_LOG = PROJECT_ROOT / "ingest_errors.log"
MAX_PRINTED_MESSAGES = 10

COLUMNS = [
    "product", "month", "attack_type", "action", "malware_name",
    "source_country", "client_sector", "severity", "count",
]
ATTACK_TYPES = {
    "intrusion_attempt", "brute_force", "malware_download", "c2_traffic", "phishing",
    "malware_attachment", "bec", "malware_execution", "ransomware", "credential_theft",
}
ACTIONS = {"blocked", "detected_only"}
SECTORS = {"Energy", "Finance", "Government", "Manufacturing", "Healthcare", "Telecom"}
SEVERITIES = {"low", "medium", "high", "critical"}

# ISO 3166-1 alpha-2: the 249 officially assigned codes.
ISO_COUNTRIES = frozenset("""
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ
EC EE EG EH ER ES ET
FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU
ID IE IL IM IN IO IQ IR IS IT
JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ
LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ
OM
PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA
RE RO RS RU RW
SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ
UA UG UM US UY UZ
VA VC VE VG VI VN VU
WF WS
YE YT
ZA ZM ZW
""".split())

MONTH_RE = re.compile(r"\d{4}-(0[1-9]|1[0-2])")
COUNT_RE = re.compile(r"\d+")

SCHEMA = """
CREATE TABLE IF NOT EXISTS products (
    product     TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    owner       TEXT NOT NULL,
    description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS malware_aliases (
    product         TEXT NOT NULL REFERENCES products(product),
    alias           TEXT NOT NULL,
    canonical_family TEXT NOT NULL,
    PRIMARY KEY (product, alias)
);
CREATE TABLE IF NOT EXISTS load_log (
    load_id   INTEGER PRIMARY KEY,
    file      TEXT NOT NULL,
    sha256    TEXT NOT NULL UNIQUE,
    product   TEXT NOT NULL REFERENCES products(product),
    year      INTEGER NOT NULL,
    rows      INTEGER NOT NULL,
    loaded_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events_monthly (
    id             INTEGER PRIMARY KEY,
    load_id        INTEGER NOT NULL REFERENCES load_log(load_id),
    product        TEXT NOT NULL,
    year           INTEGER NOT NULL,
    month          TEXT NOT NULL,
    attack_type    TEXT NOT NULL,
    action         TEXT NOT NULL,
    malware_name   TEXT,
    source_country TEXT NOT NULL,
    client_sector  TEXT NOT NULL,
    severity       TEXT NOT NULL,
    count          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_year_product_type
    ON events_monthly (year, product, attack_type);
"""


class ReferenceDataError(Exception):
    """Reference data is missing or malformed; ingestion cannot continue."""


@dataclass
class FileResult:
    file: str
    status: str  # LOADED, SKIPPED or REJECTED
    messages: list[str] = field(default_factory=list)
    rows: int = 0


@dataclass
class Validation:
    sha256: str
    rows: list[tuple] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    product: str | None = None
    year: int | None = None


# --- database -----------------------------------------------------------------

def db_path() -> Path:
    path = Path(os.environ.get("REPORT_DB", "").strip() or DEFAULT_DB)
    return path if path.is_absolute() else PROJECT_ROOT / path


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


# --- reference data -------------------------------------------------------------

def _read_reference(path: Path, columns: list[str]) -> list[dict]:
    if not path.is_file():
        raise ReferenceDataError(f"{path}: reference file not found")
    with path.open(encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != columns:
            raise ReferenceDataError(
                f"{path}: header must be {','.join(columns)}, got {','.join(reader.fieldnames or [])}"
            )
        rows = list(reader)
    for i, row in enumerate(rows, start=2):
        if any(not (row[c] or "").strip() for c in columns if c != "description"):
            raise ReferenceDataError(f"{path}: line {i}: empty value")
    return rows


def load_reference(conn: sqlite3.Connection, ref_dir: Path = REFERENCE_DIR) -> None:
    """Upsert products and malware aliases. Raises ReferenceDataError on bad data."""
    products = _read_reference(ref_dir / "products.csv", ["product", "category", "owner", "description"])
    aliases = _read_reference(ref_dir / "malware_aliases.csv", ["product", "alias", "canonical_family"])
    known = {p["product"] for p in products} | {
        r[0] for r in conn.execute("SELECT product FROM products")
    }
    for i, a in enumerate(aliases, start=2):
        if a["product"] not in known:
            raise ReferenceDataError(f"malware_aliases.csv: line {i}: unknown product '{a['product']}'")
    with conn:
        conn.executemany(
            """INSERT INTO products (product, category, owner, description)
               VALUES (:product, :category, :owner, :description)
               ON CONFLICT(product) DO UPDATE SET category = excluded.category,
                   owner = excluded.owner, description = excluded.description""",
            products,
        )
        conn.executemany(
            """INSERT INTO malware_aliases (product, alias, canonical_family)
               VALUES (:product, :alias, :canonical_family)
               ON CONFLICT(product, alias) DO UPDATE SET canonical_family = excluded.canonical_family""",
            aliases,
        )


# --- validation -------------------------------------------------------------------

def _check_row(values: list[str], line: int, known_products: set[str]) -> list[str]:
    product, month, attack_type, action, _malware, country, sector, severity, count = values
    errors = []

    def bad(name, value, expected):
        errors.append(f"line {line}: invalid {name} '{value}' (expected {expected})")

    if product not in known_products:
        bad("product", product, "a product from products.csv")
    if not MONTH_RE.fullmatch(month):
        bad("month", month, "YYYY-MM")
    if attack_type not in ATTACK_TYPES:
        bad("attack_type", attack_type, "one of " + ", ".join(sorted(ATTACK_TYPES)))
    if action not in ACTIONS:
        bad("action", action, "one of " + ", ".join(sorted(ACTIONS)))
    if country not in ISO_COUNTRIES:
        bad("source_country", country, "a two-letter uppercase ISO 3166 code")
    if sector not in SECTORS:
        bad("client_sector", sector, "one of " + ", ".join(sorted(SECTORS)))
    if severity not in SEVERITIES:
        bad("severity", severity, "one of " + ", ".join(sorted(SEVERITIES)))
    if not COUNT_RE.fullmatch(count):
        bad("count", count, "a whole number >= 0")
    return errors


def validate(data: bytes, known_products: set[str]) -> Validation:
    """Check a delivery against SPEC section 2. Collects every error found."""
    result = Validation(sha256=hashlib.sha256(data).hexdigest())
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        result.errors.append(f"file is not valid UTF-8 ({exc.reason} at byte {exc.start})")
        return result

    reader = csv.reader(io.StringIO(text, newline=""))
    header = next(reader, None)
    if header != COLUMNS:
        result.errors.append(
            f"line 1: header must be exactly {','.join(COLUMNS)}, got {','.join(header or [])!r}"
        )
        return result

    seen_keys: dict[tuple, int] = {}
    first: dict[str, tuple[str, int]] = {}  # product/year -> (value, line) of first valid row
    for values in reader:
        line = reader.line_num
        if not values:  # blank line
            continue
        if len(values) != len(COLUMNS):
            result.errors.append(f"line {line}: expected {len(COLUMNS)} columns, got {len(values)}")
            continue
        row_errors = _check_row(values, line, known_products)
        result.errors.extend(row_errors)

        key = tuple(values[:-1])
        if key in seen_keys:
            result.errors.append(f"line {line}: duplicate of line {seen_keys[key]} (same values except count)")
        else:
            seen_keys[key] = line

        product, month = values[0], values[1]
        for name, value, ok in (
            ("product", product, product in known_products),
            ("year", month[:4], bool(MONTH_RE.fullmatch(month))),
        ):
            if not ok:
                continue
            if name not in first:
                first[name] = (value, line)
            elif value != first[name][0]:
                result.errors.append(
                    f"line {line}: {name} '{value}' differs from '{first[name][0]}' on line "
                    f"{first[name][1]} (a file must contain exactly one {name})"
                )

        if not row_errors:
            p, m, at, ac, mw, c, s, sv, n = values
            result.rows.append((p, int(m[:4]), m, at, ac, mw or None, c, s, sv, int(n)))

    if not seen_keys and not result.errors:
        result.errors.append("file has a header but no data rows")
    if "product" in first:
        result.product = first["product"][0]
    if "year" in first:
        result.year = int(first["year"][0])
    return result


# --- loading ------------------------------------------------------------------------

def _display_name(path: Path) -> str:
    try:
        return path.resolve().relative_to(PROJECT_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def ingest_file(conn: sqlite3.Connection, path: Path) -> FileResult:
    name = _display_name(path)
    data = path.read_bytes()
    sha = hashlib.sha256(data).hexdigest()

    loaded = conn.execute("SELECT file FROM load_log WHERE sha256 = ?", (sha,)).fetchone()
    if loaded:
        return FileResult(name, "SKIPPED", [f"identical to already loaded file {loaded[0]}"])

    known = {r[0] for r in conn.execute("SELECT product FROM products")}
    v = validate(data, known)

    if v.product is not None and v.year is not None:
        dup = conn.execute(
            "SELECT file FROM load_log WHERE product = ? AND year = ?", (v.product, v.year)
        ).fetchone()
        if dup:
            v.errors.append(
                f"{v.product} {v.year} is already loaded from {dup[0]}; "
                "loading it again would count the data twice"
            )

    if v.errors:
        return FileResult(name, "REJECTED", v.errors)

    loaded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with conn:  # one transaction per file
        cur = conn.execute(
            "INSERT INTO load_log (file, sha256, product, year, rows, loaded_at) VALUES (?, ?, ?, ?, ?, ?)",
            (name, sha, v.product, v.year, len(v.rows), loaded_at),
        )
        conn.executemany(
            """INSERT INTO events_monthly (load_id, product, year, month, attack_type, action,
                   malware_name, source_country, client_sector, severity, count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [(cur.lastrowid, *row) for row in v.rows],
        )
    return FileResult(name, "LOADED", [f"{len(v.rows)} rows, {v.product} {v.year}"], rows=len(v.rows))


def format_result(r: FileResult) -> str:
    lines = [f"{r.status:<8} {r.file}"]
    shown = r.messages[:MAX_PRINTED_MESSAGES]
    lines += [f"         {m}" for m in shown]
    if len(r.messages) > len(shown):
        lines.append(f"         ... and {len(r.messages) - len(shown)} more (see ingest_errors.log)")
    return "\n".join(lines)


def log_rejection(r: FileResult, log_path: Path) -> None:
    stamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with log_path.open("a", encoding="utf-8") as f:
        f.write(f"{stamp} REJECTED {r.file} ({len(r.messages)} errors)\n")
        f.writelines(f"  {m}\n" for m in r.messages)


def run(folders: list[Path], database: Path, ref_dir: Path = REFERENCE_DIR,
        log_path: Path = ERROR_LOG, out=sys.stdout) -> int:
    for folder in folders:
        if not folder.is_dir():
            print(f"ERROR: folder not found: {folder}", file=out)
            return 2
    conn = connect(database)
    try:
        try:
            load_reference(conn, ref_dir)
        except ReferenceDataError as exc:
            print(f"ERROR: reference data: {exc}", file=out)
            return 2
        rejected = False
        for folder in folders:
            files = sorted(folder.glob("*.csv"))
            if not files:
                print(f"(no .csv files in {_display_name(folder)})", file=out)
            for path in files:
                result = ingest_file(conn, path)
                print(format_result(result), file=out)
                if result.status == "REJECTED":
                    rejected = True
                    log_rejection(result, log_path)
        return 1 if rejected else 0
    finally:
        conn.close()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if any(a in ("-h", "--help") for a in args):
        print(__doc__)
        return 0
    folders = [Path(a) for a in args] or [DEFAULT_FOLDER]
    return run(folders, db_path())


if __name__ == "__main__":
    sys.exit(main())
