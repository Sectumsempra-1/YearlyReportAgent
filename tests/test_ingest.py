"""Tests for ingest.py. Uses a temporary database; data/ is only read."""

import io
import sqlite3
from pathlib import Path

import pytest

import ingest

ROOT = Path(__file__).resolve().parent.parent
EXPORTS = ROOT / "data" / "exports"
BAD = ROOT / "data" / "exports_bad"

HEADER = ",".join(ingest.COLUMNS)
GOOD_ROW = "EDR,2026-05,ransomware,blocked,Win32/Akira.gen,BR,Energy,critical,12"


# --- helpers ------------------------------------------------------------------------

@pytest.fixture
def db(tmp_path):
    path = tmp_path / "report.db"
    conn = ingest.connect(path)
    ingest.load_reference(conn)
    yield conn
    conn.close()


def write_csv(folder: Path, name: str, rows: list[str], header: str = HEADER, bom=False) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    text = "\n".join([header, *rows]) + "\n"
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))
    return path


def row(**changes) -> str:
    values = dict(zip(ingest.COLUMNS, GOOD_ROW.split(",")))
    values.update(changes)
    return ",".join(values[c] for c in ingest.COLUMNS)


def event_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM events_monthly").fetchone()[0]


def run_cli(tmp_path, *folders):
    out = io.StringIO()
    code = ingest.run(list(folders), tmp_path / "report.db",
                      log_path=tmp_path / "ingest_errors.log", out=out)
    return code, out.getvalue()


# --- valid files ------------------------------------------------------------------------

def test_valid_file_loads(db, tmp_path):
    path = write_csv(tmp_path, "edr_2026.csv", [GOOD_ROW, row(month="2026-06", count="0")])
    result = ingest.ingest_file(db, path)
    assert result.status == "LOADED"
    assert result.rows == 2
    log = db.execute("SELECT product, year, rows, sha256, loaded_at FROM load_log").fetchone()
    assert log[:3] == ("EDR", 2026, 2)
    assert len(log[3]) == 64
    assert log[4].endswith("+00:00")  # UTC ISO
    stored = db.execute(
        "SELECT product, year, month, malware_name, source_country, count FROM events_monthly ORDER BY id"
    ).fetchall()
    assert stored == [("EDR", 2026, "2026-05", "Win32/Akira.gen", "BR", 12),
                      ("EDR", 2026, "2026-06", "Win32/Akira.gen", "BR", 0)]


def test_empty_malware_name_stored_as_null(db, tmp_path):
    ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [row(malware_name="")]))
    assert db.execute("SELECT malware_name FROM events_monthly").fetchone()[0] is None


def test_utf8_bom_is_accepted(db, tmp_path):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW], bom=True))
    assert result.status == "LOADED"


def test_all_real_exports_load(tmp_path):
    code, out = run_cli(tmp_path, EXPORTS)
    assert code == 0
    assert out.count("LOADED") == 6
    conn = sqlite3.connect(tmp_path / "report.db")
    for path in EXPORTS.glob("*.csv"):
        expected = len(path.read_text(encoding="utf-8").splitlines()) - 1
        loaded = conn.execute(
            "SELECT rows FROM load_log WHERE file = ?", (f"data/exports/{path.name}",)
        ).fetchone()[0]
        assert loaded == expected, path.name
    conn.close()


# --- invalid rows: each kind is caught with a clear message -------------------------------

@pytest.mark.parametrize("changes, expected", [
    ({"product": "Antivirus"}, "line 2: invalid product 'Antivirus'"),
    ({"month": "2026-13"}, "line 2: invalid month '2026-13' (expected YYYY-MM)"),
    ({"month": "2026-00"}, "line 2: invalid month '2026-00'"),
    ({"month": "2026-5"}, "line 2: invalid month '2026-5'"),
    ({"month": "May 2026"}, "line 2: invalid month 'May 2026'"),
    ({"attack_type": "ddos"}, "line 2: invalid attack_type 'ddos'"),
    ({"action": "quarantined"}, "line 2: invalid action 'quarantined'"),
    ({"action": "Blocked"}, "line 2: invalid action 'Blocked'"),
    ({"source_country": "Brazil"}, "line 2: invalid source_country 'Brazil'"),
    ({"source_country": "br"}, "line 2: invalid source_country 'br'"),
    ({"source_country": "XX"}, "line 2: invalid source_country 'XX'"),
    ({"source_country": ""}, "line 2: invalid source_country ''"),
    ({"client_sector": "Retail"}, "line 2: invalid client_sector 'Retail'"),
    ({"severity": "urgent"}, "line 2: invalid severity 'urgent'"),
    ({"count": "-5"}, "line 2: invalid count '-5' (expected a whole number >= 0)"),
    ({"count": "3.5"}, "line 2: invalid count '3.5'"),
    ({"count": ""}, "line 2: invalid count ''"),
    ({"count": "ten"}, "line 2: invalid count 'ten'"),
])
def test_invalid_value_is_caught(db, tmp_path, changes, expected):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [row(**changes)]))
    assert result.status == "REJECTED"
    assert any(m.startswith(expected) for m in result.messages), result.messages


def test_wrong_column_count(db, tmp_path):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW + ",extra"]))
    assert result.messages == ["line 2: expected 9 columns, got 10"]


@pytest.mark.parametrize("header", [
    HEADER.replace("count", "total"),                       # renamed column
    ",".join(reversed(ingest.COLUMNS)),                     # wrong order
    ",".join(ingest.COLUMNS[:-1]),                          # missing column
])
def test_wrong_header(db, tmp_path, header):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW], header=header))
    assert result.status == "REJECTED"
    assert result.messages[0].startswith("line 1: header must be exactly")


def test_header_only_file(db, tmp_path):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", []))
    assert result.messages == ["file has a header but no data rows"]


def test_duplicate_row(db, tmp_path):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW, row(count="99")]))
    assert result.messages == ["line 3: duplicate of line 2 (same values except count)"]


def test_more_than_one_product(db, tmp_path):
    other = "Firewall,2026-05,intrusion_attempt,blocked,,BR,Energy,high,5"
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW, other]))
    assert result.messages == [
        "line 3: product 'Firewall' differs from 'EDR' on line 2 (a file must contain exactly one product)"
    ]


def test_more_than_one_year(db, tmp_path):
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", [GOOD_ROW, row(month="2025-05")]))
    assert result.messages == [
        "line 3: year '2025' differs from '2026' on line 2 (a file must contain exactly one year)"
    ]


def test_not_utf8(db, tmp_path):
    path = tmp_path / "f.csv"
    path.write_bytes((HEADER + "\n" + GOOD_ROW.replace("BR", "\xe9\xe9")).encode("latin-1"))
    result = ingest.ingest_file(db, path)
    assert result.status == "REJECTED"
    assert result.messages[0].startswith("file is not valid UTF-8")


def test_all_errors_are_collected(db, tmp_path):
    rows = [GOOD_ROW, row(month="2026-13"), row(action="quarantined", month="2026-01"),
            row(severity="x", count="-1", month="2026-02")]
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", rows))
    lines = [m.split(":")[0] for m in result.messages]
    assert lines == ["line 3", "line 4", "line 5", "line 5"]


# --- a file with any error loads nothing -----------------------------------------------------

def test_one_bad_row_rejects_the_whole_file(db, tmp_path):
    rows = [row(month=f"2026-{m:02d}") for m in range(1, 12)] + [row(month="2026-12", count="-1")]
    result = ingest.ingest_file(db, write_csv(tmp_path, "f.csv", rows))
    assert result.status == "REJECTED"
    assert event_count(db) == 0
    assert db.execute("SELECT COUNT(*) FROM load_log").fetchone()[0] == 0


def test_provided_bad_file_on_empty_database(tmp_path):
    code, out = run_cli(tmp_path, BAD)
    assert code == 1
    assert "REJECTED" in out
    conn = sqlite3.connect(tmp_path / "report.db")
    assert event_count(conn) == 0
    conn.close()
    log = (tmp_path / "ingest_errors.log").read_text(encoding="utf-8")
    for expected in ["line 3: invalid month '2026-13'", "line 4: invalid action 'quarantined'",
                     "line 5: invalid source_country 'Brazil'", "line 6: invalid count '-5'"]:
        assert expected in log
    assert "(4 errors)" in log


def test_provided_bad_file_after_exports(tmp_path):
    run_cli(tmp_path, EXPORTS)
    code, out = run_cli(tmp_path, BAD)
    assert code == 1
    log = (tmp_path / "ingest_errors.log").read_text(encoding="utf-8")
    assert "(5 errors)" in log
    assert "EDR 2026 is already loaded from data/exports/edr_2026.csv" in log


# --- duplicates across files ------------------------------------------------------------------

def test_same_file_twice_is_skipped(db, tmp_path):
    path = write_csv(tmp_path, "f.csv", [GOOD_ROW])
    assert ingest.ingest_file(db, path).status == "LOADED"
    second = ingest.ingest_file(db, path)
    assert second.status == "SKIPPED"
    assert event_count(db) == 1


def test_same_content_under_another_name_is_skipped(db, tmp_path):
    ingest.ingest_file(db, write_csv(tmp_path / "a", "edr_2026.csv", [GOOD_ROW]))
    result = ingest.ingest_file(db, write_csv(tmp_path / "b", "copy.csv", [GOOD_ROW]))
    assert result.status == "SKIPPED"


def test_second_file_for_same_product_and_year_is_rejected(db, tmp_path):
    ingest.ingest_file(db, write_csv(tmp_path / "a", "edr_2026.csv", [GOOD_ROW]))
    result = ingest.ingest_file(db, write_csv(tmp_path / "b", "edr_2026_v2.csv", [row(count="13")]))
    assert result.status == "REJECTED"
    assert "EDR 2026 is already loaded" in result.messages[0]
    assert event_count(db) == 1


def test_same_product_other_year_loads(db, tmp_path):
    ingest.ingest_file(db, write_csv(tmp_path / "a", "edr_2026.csv", [GOOD_ROW]))
    result = ingest.ingest_file(db, write_csv(tmp_path / "b", "edr_2025.csv", [row(month="2025-05")]))
    assert result.status == "LOADED"


def test_rerunning_exports_skips_everything(tmp_path):
    run_cli(tmp_path, EXPORTS)
    code, out = run_cli(tmp_path, EXPORTS)
    assert code == 0
    assert out.count("SKIPPED") == 6
    conn = sqlite3.connect(tmp_path / "report.db")
    assert conn.execute("SELECT COUNT(*) FROM load_log").fetchone()[0] == 6
    conn.close()


# --- reference data, schema and CLI -----------------------------------------------------------

def test_reference_upsert_is_idempotent(db):
    ingest.load_reference(db)
    assert db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 3
    assert db.execute("SELECT COUNT(*) FROM malware_aliases").fetchone()[0] == 30


def test_reference_alias_for_unknown_product_fails(tmp_path):
    ref = tmp_path / "ref"
    ref.mkdir()
    (ref / "products.csv").write_text("product,category,owner,description\nEDR,Endpoint,Team,x\n")
    (ref / "malware_aliases.csv").write_text("product,alias,canonical_family\nNope,a,b\n")
    conn = ingest.connect(tmp_path / "r.db")
    with pytest.raises(ingest.ReferenceDataError, match="unknown product 'Nope'"):
        ingest.load_reference(conn, ref)
    conn.close()


def test_index_exists(db):
    cols = [r[2] for r in db.execute("PRAGMA index_info(idx_events_year_product_type)")]
    assert cols == ["year", "product", "attack_type"]


def test_printed_messages_are_capped_at_ten(tmp_path):
    folder = tmp_path / "in"
    write_csv(folder, "f.csv", [row(month=f"2026-{m:02d}", count="-1") for m in range(1, 13)])
    code, out = run_cli(tmp_path, folder)
    assert code == 1
    assert out.count("invalid count") == 10
    assert "... and 2 more (see ingest_errors.log)" in out
    assert (tmp_path / "ingest_errors.log").read_text().count("invalid count") == 12


def test_missing_folder(tmp_path):
    code, out = run_cli(tmp_path, tmp_path / "nope")
    assert code == 2
    assert "folder not found" in out


def test_db_path_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("REPORT_DB", str(tmp_path / "x.db"))
    assert ingest.db_path() == tmp_path / "x.db"
    monkeypatch.setenv("REPORT_DB", "data/other.db")
    assert ingest.db_path() == ingest.PROJECT_ROOT / "data" / "other.db"
    monkeypatch.delenv("REPORT_DB")
    assert ingest.db_path() == ingest.PROJECT_ROOT / "data" / "report.db"
