"""Tests for report_tools.py.

Most tests use a small database with known values (built through ingest.py),
so every expected number below was worked out by hand from FIXTURE. A second
small database tests monthly spikes, and a copy of the real exports is used
for consistency checks only.
"""

import io
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path

import pytest

import ingest
import report_tools as rt

ROOT = Path(__file__).resolve().parent.parent
HEADER = ",".join(ingest.COLUMNS)

# Email Gateway has no 2025 file, to test partial and missing previous-year data.
FIXTURE = {
    "firewall_2025.csv": [
        "Firewall,2025-01,intrusion_attempt,blocked,,CN,Energy,high,100",
        "Firewall,2025-02,intrusion_attempt,blocked,,RU,Finance,high,50",
        "Firewall,2025-01,malware_download,blocked,Mal/Emotet,US,Energy,medium,30",
    ],
    "edr_2025.csv": [
        "EDR,2025-01,ransomware,blocked,Win32/LockBit.gen,CN,Energy,critical,40",
        "EDR,2025-01,ransomware,detected_only,Win32/LockBit.gen,CN,Energy,critical,10",
        "EDR,2025-03,malware_execution,blocked,Win32/Emotet.gen,RU,Finance,high,20",
    ],
    "firewall_2026.csv": [
        "Firewall,2026-01,intrusion_attempt,blocked,,CN,Energy,high,120",
        "Firewall,2026-02,intrusion_attempt,blocked,,RU,Finance,high,40",
        "Firewall,2026-03,malware_download,blocked,Mal/Emotet,US,Energy,medium,30",
        "Firewall,2026-03,c2_traffic,blocked,Mal/Qakbot,DE,Telecom,critical,60",
    ],
    "edr_2026.csv": [
        "EDR,2026-01,ransomware,blocked,Win32/LockBit.gen,CN,Energy,critical,30",
        "EDR,2026-01,ransomware,detected_only,Win32/LockBit.gen,CN,Energy,critical,10",
        "EDR,2026-02,malware_execution,blocked,Win32/Emotet.gen,RU,Finance,high,25",
        "EDR,2026-02,malware_execution,blocked,Win32/NewThing.gen,BR,Healthcare,high,5",
        "EDR,2026-02,malware_execution,detected_only,Win32/NewThing.gen,BR,Healthcare,high,5",
    ],
    "email_gateway_2026.csv": [
        "Email Gateway,2026-01,phishing,blocked,,CN,Finance,medium,200",
        "Email Gateway,2026-01,phishing,detected_only,,CN,Finance,medium,20",
        "Email Gateway,2026-04,malware_attachment,blocked,Trojan.Emotet,US,Government,high,10",
    ],
}

# EDR ransomware: 8 blocked every month of 2025; 2026 is flat at 10 with a spike and a dip.
MONTHLY_2026 = [10] * 10 + [30, 5]
MONTHLY_FIXTURE = {
    "edr_2025.csv": [f"EDR,2025-{m:02d},ransomware,blocked,,CN,Energy,critical,8" for m in range(1, 13)]
    # reported in 2025 only, and detected_only so the blocked series is unaffected
    + ["EDR,2025-06,credential_theft,detected_only,,CN,Energy,high,4"],
    "edr_2026.csv": [f"EDR,2026-{m:02d},ransomware,blocked,,CN,Energy,critical,{c}"
                     for m, c in enumerate(MONTHLY_2026, 1)],
}

NO_PREV_2025 = "No data is loaded for 2025, so no year-over-year comparison is possible."
PARTIAL_PREV = "No data is loaded for 2025 from Email Gateway, so previous-year values exclude it."


def build_db(folder: Path, files: dict[str, list[str]] | None = None, source: Path | None = None) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    if files:
        for name, rows in files.items():
            (folder / name).write_text("\n".join([HEADER, *rows]) + "\n", encoding="utf-8")
    db = folder / "report.db"
    code = ingest.run([source or folder], db, log_path=folder / "errors.log", out=io.StringIO())
    assert code == 0
    return db


@pytest.fixture(scope="module")
def known_db(tmp_path_factory):
    return build_db(tmp_path_factory.mktemp("known"), FIXTURE)


@pytest.fixture(scope="module")
def monthly_db(tmp_path_factory):
    return build_db(tmp_path_factory.mktemp("monthly"), MONTHLY_FIXTURE)


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    return build_db(tmp_path_factory.mktemp("real"), source=ROOT / "data" / "exports")


@pytest.fixture
def known(known_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(known_db))


@pytest.fixture
def monthly(monthly_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(monthly_db))


@pytest.fixture
def real(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


def rows_by(result, field):
    return {r[field]: r for r in result["value"]["rows"]}


# --- rounding --------------------------------------------------------------------------------

def test_rounding_is_half_up():
    assert rt.round_half_up(12.25) == 12.3
    assert rt.round_half_up(0.05) == 0.1          # round() gives 0.1 or 0.0 depending on float
    assert rt.round_half_up(2.675, 2) == 2.68      # round(2.675, 2) gives 2.67
    assert rt.round_half_up(-12.25) == -12.3
    assert rt.round_half_up(None) is None


def test_pct():
    assert rt.pct(1, 2000) == 0.1                  # exactly 0.05 -> 0.1
    assert rt.pct(-1, 2000) == -0.1
    assert rt.pct(1, 3) == 33.3
    assert rt.pct(2, 3) == 66.7
    assert rt.pct(5, 0) is None


# --- result shape, source and read-only access ------------------------------------------------

def test_tools_list():
    assert [f.__name__ for f in rt.TOOLS] == [
        "list_products", "attacks_blocked", "compare_years", "product_summary", "attack_type_changes",
        "top_malware", "unmapped_malware", "top_countries", "monthly_series", "sector_breakdown",
        "severity_breakdown",
    ]


def test_result_shape_and_source_params(known):
    result = rt.compare_years(2026, product="Firewall")
    assert set(result) == {"value", "source", "caveats"}
    assert result["source"] == {"function": "compare_years",
                                "params": {"year": 2026, "product": "Firewall", "attack_type": None}}
    assert rt.top_malware(2026)["source"]["params"] == {"year": 2026, "n": 10, "product": None}
    assert rt.monthly_series(2026)["source"]["params"]["spike_factor"] == 1.5


def test_connection_is_read_only(known, known_db):
    before = sqlite3.connect(known_db).execute("SELECT COUNT(*) FROM products").fetchone()[0]
    with rt._connect() as conn:
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("INSERT INTO products VALUES ('X', 'c', 'o', 'd')")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("DELETE FROM events_monthly")
        with pytest.raises(sqlite3.OperationalError, match="readonly"):
            conn.execute("CREATE TABLE t (x)")
    after = sqlite3.connect(known_db).execute("SELECT COUNT(*) FROM products").fetchone()[0]
    assert before == after


def test_missing_database_is_not_created(tmp_path, monkeypatch):
    missing = tmp_path / "nope.db"
    monkeypatch.setenv("REPORT_DB", str(missing))
    with pytest.raises(FileNotFoundError, match="python ingest.py"):
        rt.attacks_blocked(2026)
    assert not missing.exists()


@pytest.mark.parametrize("call, message", [
    (lambda: rt.attacks_blocked(2026, product="Antivirus"), "unknown product 'Antivirus'"),
    (lambda: rt.attacks_blocked(2026, attack_type="ddos"), "unknown attack_type 'ddos'"),
    (lambda: rt.attacks_blocked("2026"), "year must be an integer"),
    (lambda: rt.top_malware(2026, n=0), "n must be a positive integer"),
    (lambda: rt.monthly_series(2026, spike_factor=0), "spike_factor must be a positive number"),
    (lambda: rt.product_summary(2026, None), "product is required"),
])
def test_invalid_arguments(known, call, message):
    with pytest.raises(ValueError, match=message):
        call()


# --- list_products ------------------------------------------------------------------------------

def test_list_products(known):
    result = rt.list_products()
    by_product = {r["product"]: r for r in result["value"]}
    assert by_product["EDR"]["attack_types"] == ["malware_execution", "ransomware"]
    assert by_product["EDR"]["years_loaded"] == [2025, 2026]
    assert by_product["Email Gateway"]["years_loaded"] == [2026]
    assert by_product["Firewall"]["attack_types"] == ["c2_traffic", "intrusion_attempt", "malware_download"]
    assert by_product["Firewall"]["category"] == "Network"
    assert result["caveats"] == []


# --- attacks_blocked and compare_years ------------------------------------------------------------

def test_attacks_blocked(known):
    assert rt.attacks_blocked(2026)["value"] == 520
    assert rt.attacks_blocked(2026, product="Firewall")["value"] == 250
    assert rt.attacks_blocked(2026, product="EDR", attack_type="malware_execution")["value"] == 30
    assert rt.attacks_blocked(2026, attack_type="bec")["value"] == 0


def test_attacks_blocked_caveats(known):
    assert rt.attacks_blocked(2026)["caveats"] == [rt.CAVEAT_CROSS_PRODUCT]
    assert rt.attacks_blocked(2026, product="EDR")["caveats"] == []
    assert rt.attacks_blocked(2025)["caveats"] == [
        rt.CAVEAT_CROSS_PRODUCT, "No data is loaded for 2025 from: Email Gateway."]
    assert rt.attacks_blocked(2025, product="Email Gateway")["caveats"] == [
        "No data is loaded for Email Gateway in 2025."]


def test_compare_years_single_product(known):
    assert rt.compare_years(2026, product="Firewall")["value"] == {
        "current": 250, "previous": 180, "change": 70, "pct_change": 38.9}
    assert rt.compare_years(2026, product="EDR")["value"] == {
        "current": 60, "previous": 60, "change": 0, "pct_change": 0.0}
    assert rt.compare_years(2026, product="EDR", attack_type="ransomware")["value"] == {
        "current": 30, "previous": 40, "change": -10, "pct_change": -25.0}


def test_compare_years_previous_zero_is_not_missing(known):
    result = rt.compare_years(2026, product="Firewall", attack_type="c2_traffic")
    assert result["value"] == {"current": 60, "previous": 0, "change": 60, "pct_change": None}
    assert result["caveats"] == []


def test_compare_years_previous_year_not_loaded(known):
    result = rt.compare_years(2026, product="Email Gateway")
    assert result["value"] == {"current": 210, "previous": None, "change": None, "pct_change": None}
    assert result["caveats"] == [NO_PREV_2025]
    # All products, but only Email Gateway reports phishing
    assert rt.compare_years(2026, attack_type="phishing")["value"]["previous"] is None
    # No product has 2024 data
    result = rt.compare_years(2025)
    assert result["value"]["previous"] is None
    assert "No data is loaded for 2024, so no year-over-year comparison is possible." in result["caveats"]


def test_compare_years_partial_previous_year(known):
    result = rt.compare_years(2026)
    assert result["value"] == {"current": 520, "previous": 240, "change": 280, "pct_change": 116.7}
    assert result["caveats"] == [rt.CAVEAT_CROSS_PRODUCT, PARTIAL_PREV]


# --- product_summary --------------------------------------------------------------------------------

def test_product_summary(known):
    result = rt.product_summary(2026, "EDR")
    assert result["value"] == {
        "malware_execution": {
            "blocked": 30, "detected_only": 5, "block_rate_pct": 85.7,
            "yoy_blocked": {"current": 30, "previous": 20, "change": 10, "pct_change": 50.0},
            "by_severity": {"low": 0, "medium": 0, "high": 35, "critical": 0},
        },
        "ransomware": {
            "blocked": 30, "detected_only": 10, "block_rate_pct": 75.0,
            "yoy_blocked": {"current": 30, "previous": 40, "change": -10, "pct_change": -25.0},
            "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 40},
        },
    }
    assert result["caveats"] == []


def test_product_summary_blocked_only_product(known):
    result = rt.product_summary(2026, "Firewall")
    assert set(result["value"]) == {"c2_traffic", "intrusion_attempt", "malware_download"}
    assert all(v["block_rate_pct"] is None for v in result["value"].values())
    assert result["value"]["intrusion_attempt"]["yoy_blocked"]["pct_change"] == 6.7
    assert result["caveats"] == [rt.CAVEAT_BLOCKED_ONLY]


def test_product_summary_without_previous_year(known):
    result = rt.product_summary(2026, "Email Gateway")
    assert result["value"]["phishing"]["block_rate_pct"] == 90.9
    assert result["value"]["phishing"]["yoy_blocked"]["previous"] is None
    assert result["caveats"] == [NO_PREV_2025]


def test_product_summary_keeps_attack_type_that_disappeared(monthly):
    result = rt.product_summary(2026, "EDR")
    assert result["value"]["credential_theft"] == {
        "blocked": 0, "detected_only": 0, "block_rate_pct": None,
        "yoy_blocked": {"current": 0, "previous": 0, "change": 0, "pct_change": None},
        "by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    }


# --- attack_type_changes -------------------------------------------------------------------------------

def test_attack_type_changes(known):
    rows = rt.attack_type_changes(2026)["value"]["rows"]
    assert [(r["rank"], r["attack_type"], r["pct_change"]) for r in rows] == [
        (1, "malware_execution", 50.0),
        (2, "intrusion_attempt", 6.7),
        (3, "malware_download", 0.0),
        (4, "ransomware", -25.0),
        (None, "c2_traffic", None),          # previous 0: new
        (None, "malware_attachment", None),  # previous year not loaded
        (None, "phishing", None),
    ]
    by_type = {r["attack_type"]: r for r in rows}
    assert by_type["c2_traffic"]["previous"] == 0
    assert by_type["phishing"]["previous"] is None


def test_attack_type_changes_caveats(known):
    caveats = rt.attack_type_changes(2026)["caveats"]
    assert caveats[0] == rt.CAVEAT_CROSS_PRODUCT
    assert NO_PREV_2025 in caveats
    assert rt.attack_type_changes(2026, product="EDR")["caveats"] == []


# --- top_malware and unmapped_malware ----------------------------------------------------------------

def test_top_malware(known):
    result = rt.top_malware(2026)
    assert result["value"]["total"] == 175
    assert result["value"]["rows"] == [
        {"rank": 1, "family": "Emotet", "volume": 65, "share_pct": 37.1, "previous_volume": 50,
         "pct_change": 30.0, "previous_rank": 1, "new_this_year": False},
        {"rank": 2, "family": "Qakbot", "volume": 60, "share_pct": 34.3, "previous_volume": 0,
         "pct_change": None, "previous_rank": None, "new_this_year": True},
        {"rank": 3, "family": "LockBit", "volume": 40, "share_pct": 22.9, "previous_volume": 50,
         "pct_change": -20.0, "previous_rank": 1, "new_this_year": False},
        {"rank": 4, "family": "UNMAPPED:Win32/NewThing.gen", "volume": 10, "share_pct": 5.7,
         "previous_volume": 0, "pct_change": None, "previous_rank": None, "new_this_year": True},
    ]


def test_top_malware_previous_ranks_share_ties(known):
    # 2025: Emotet 50 and LockBit 50 tie at rank 1, listed alphabetically
    rows = rt.top_malware(2025)["value"]["rows"]
    assert [(r["rank"], r["family"]) for r in rows] == [(1, "Emotet"), (1, "LockBit")]


def test_top_malware_n_limits_rows_not_total(known):
    result = rt.top_malware(2026, n=2)
    assert [r["family"] for r in result["value"]["rows"]] == ["Emotet", "Qakbot"]
    assert result["value"]["total"] == 175
    assert result["value"]["rows"][0]["share_pct"] == 37.1
    # The unmapped name is outside the top 2 but still in the full list
    assert rt.CAVEAT_UNMAPPED in result["caveats"]


def test_top_malware_caveats(known):
    assert rt.top_malware(2026)["caveats"] == [rt.CAVEAT_CROSS_PRODUCT, PARTIAL_PREV, rt.CAVEAT_UNMAPPED]
    assert rt.top_malware(2026, product="Firewall")["caveats"] == []
    assert rt.CAVEAT_UNMAPPED not in rt.top_malware(2025)["caveats"]


def test_top_malware_for_one_product(known):
    rows = rt.top_malware(2026, product="EDR")["value"]["rows"]
    assert [(r["family"], r["volume"]) for r in rows] == [
        ("LockBit", 40), ("Emotet", 25), ("UNMAPPED:Win32/NewThing.gen", 10)]


def test_unmapped_malware(known):
    result = rt.unmapped_malware(2026)
    assert result["value"]["rows"] == [{"product": "EDR", "vendor_name": "Win32/NewThing.gen", "detections": 10}]
    assert rt.unmapped_malware(2026, product="Firewall")["value"]["rows"] == []
    assert rt.unmapped_malware(2025)["value"]["rows"] == []


# --- top_countries, sector_breakdown, severity_breakdown ------------------------------------------------

def test_top_countries(known):
    result = rt.top_countries(2026)
    assert result["value"]["total"] == 555
    assert [(r["rank"], r["country"], r["volume"], r["share_pct"], r["previous_volume"], r["pct_change"],
             r["previous_rank"], r["new_this_year"]) for r in result["value"]["rows"]] == [
        (1, "CN", 380, 68.5, 150, 153.3, 1, False),
        (2, "RU", 65, 11.7, 70, -7.1, 2, False),
        (3, "DE", 60, 10.8, 0, None, None, True),
        (4, "US", 40, 7.2, 30, 33.3, 3, False),
        (5, "BR", 10, 1.8, 0, None, None, True),
    ]


def test_top_countries_caveats(known):
    assert rt.top_countries(2026)["caveats"] == [rt.CAVEAT_GEOLOCATION, rt.CAVEAT_CROSS_PRODUCT, PARTIAL_PREV]
    assert rt.top_countries(2026, product="EDR")["caveats"] == [rt.CAVEAT_GEOLOCATION]


def test_top_countries_without_previous_year(known):
    result = rt.top_countries(2026, product="Email Gateway")
    row = result["value"]["rows"][0]
    assert (row["country"], row["volume"]) == ("CN", 220)
    assert row["previous_volume"] is None and row["previous_rank"] is None
    assert row["pct_change"] is None and row["new_this_year"] is None
    assert NO_PREV_2025 in result["caveats"]


def test_sector_breakdown_with_current_tie(known):
    result = rt.sector_breakdown(2026)
    assert result["value"]["total"] == 555
    assert [(r["rank"], r["sector"], r["volume"], r["share_pct"], r["previous_rank"], r["pct_change"],
             r["new_this_year"]) for r in result["value"]["rows"]] == [
        (1, "Finance", 285, 51.4, 2, 307.1, False),
        (2, "Energy", 190, 34.2, 1, 5.6, False),
        (3, "Telecom", 60, 10.8, None, None, True),
        (4, "Government", 10, 1.8, None, None, True),
        (4, "Healthcare", 10, 1.8, None, None, True),
    ]
    assert result["caveats"] == [rt.CAVEAT_CROSS_PRODUCT, PARTIAL_PREV]


def test_severity_breakdown(known):
    result = rt.severity_breakdown(2026)
    assert [(r["rank"], r["severity"], r["volume"], r["share_pct"], r["previous_rank"])
            for r in result["value"]["rows"]] == [
        (1, "medium", 250, 45.0, 3),
        (2, "high", 205, 36.9, 1),
        (3, "critical", 100, 18.0, 2),
    ]


# --- monthly_series ---------------------------------------------------------------------------------------

def test_monthly_series_spike_peak_low(monthly):
    result = rt.monthly_series(2026, product="EDR")
    v = result["value"]
    assert [m["blocked"] for m in v["months"]] == MONTHLY_2026
    assert v["total"] == 135
    assert v["median"] == 10.0
    assert v["peak_month"] == "2026-11"
    assert v["low_month"] == "2026-12"
    assert v["spike_months"] == ["2026-11"]
    assert result["caveats"] == []


def test_monthly_series_changes(monthly):
    months = rt.monthly_series(2026, product="EDR")["value"]["months"]
    assert months[0] == {"month": "2026-01", "blocked": 10, "mom_change": None,
                         "mom_pct_change": None, "previous_year_blocked": 8}
    assert (months[1]["mom_change"], months[1]["mom_pct_change"]) == (0, 0.0)
    assert (months[10]["mom_change"], months[10]["mom_pct_change"]) == (20, 200.0)
    assert (months[11]["mom_change"], months[11]["mom_pct_change"]) == (-25, -83.3)
    assert all(m["previous_year_blocked"] == 8 for m in months)


def test_monthly_series_spike_factor(monthly):
    assert rt.monthly_series(2026, product="EDR", spike_factor=3)["value"]["spike_months"] == ["2026-11"]
    assert rt.monthly_series(2026, product="EDR", spike_factor=3.5)["value"]["spike_months"] == []


def test_monthly_series_gaps_and_zero_median(known):
    result = rt.monthly_series(2026)
    v = result["value"]
    assert [m["blocked"] for m in v["months"][:5]] == [350, 70, 90, 10, 0]
    assert v["peak_month"] == "2026-01"
    assert v["low_month"] == "2026-05"   # earliest of the months tied at 0
    assert v["median"] == 0.0
    assert v["spike_months"] == []
    assert v["months"][2]["mom_pct_change"] == 28.6
    assert v["months"][5]["mom_pct_change"] is None   # 0 -> 0
    assert [m["previous_year_blocked"] for m in v["months"][:4]] == [170, 50, 20, 0]
    assert "The monthly median is 0, so spike months cannot be identified." in result["caveats"]
    assert ("EDR has no rows for 2026-03, 2026-04, 2026-05, 2026-06, 2026-07, 2026-08, 2026-09, "
            "2026-10, 2026-11, 2026-12; these months are a data gap.") in result["caveats"]


def test_monthly_series_without_previous_year(known):
    result = rt.monthly_series(2026, product="Email Gateway")
    assert all(m["previous_year_blocked"] is None for m in result["value"]["months"])
    assert NO_PREV_2025 in result["caveats"]


# --- consistency on the real exports ----------------------------------------------------------------------

def test_real_data_totals_are_consistent(real):
    products = [p["product"] for p in rt.list_products()["value"]]
    total = rt.attacks_blocked(2026)["value"]
    assert sum(rt.attacks_blocked(2026, product=p)["value"] for p in products) == total
    assert rt.monthly_series(2026)["value"]["total"] == total
    for p in products:
        summary = rt.product_summary(2026, p)["value"]
        assert sum(v["blocked"] for v in summary.values()) == rt.attacks_blocked(2026, product=p)["value"]


def test_real_data_rankings_are_consistent(real):
    countries = rt.top_countries(2026, n=1000)["value"]
    sectors = rt.sector_breakdown(2026)["value"]
    severities = rt.severity_breakdown(2026)["value"]
    assert countries["total"] == sectors["total"] == severities["total"]
    for ranked in (countries, sectors, severities):
        assert abs(sum(r["share_pct"] for r in ranked["rows"]) - 100) < 0.5
        ranks = [r["rank"] for r in ranked["rows"]]
        assert ranks == sorted(ranks) and ranks[0] == 1


def test_real_data_unmapped_names_appear_in_top_malware(real):
    unmapped = rt.unmapped_malware(2026)["value"]["rows"]
    families = {r["family"] for r in rt.top_malware(2026, n=1000)["value"]["rows"]}
    for row in unmapped:
        assert f"UNMAPPED:{row['vendor_name']}" in families
    if unmapped:
        assert rt.CAVEAT_UNMAPPED in rt.top_malware(2026)["caveats"]


def test_demo_runs(real):
    out = io.StringIO()
    with redirect_stdout(out):
        rt.demo(2026)
    assert out.getvalue().count("=== ") == 14
