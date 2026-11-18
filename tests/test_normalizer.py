"""Tests for the normalizer: the code checks of SPEC 7.2 and the node with a
scripted fake model. No real model is called."""

import io
import json
from pathlib import Path

import pytest

import ingest
import report_tools as rt
from agents.attack import AttackDataMissing
from agents.nodes.normalizer import (
    MIN_CONFIDENCE, apply_confidence_threshold, check_label, labels_in_cited_data, make_normalizer,
)
from agents.state import Finding, NormalizedFinding
from agents.structured import StructuredOutputError
from tests.fakes import FakeChatModel
from tests.test_attack import BUNDLE

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def real_db(tmp_path_factory):
    folder = tmp_path_factory.mktemp("db")
    db = folder / "report.db"
    assert ingest.run([ROOT / "data" / "exports"], db, log_path=folder / "e.log", out=io.StringIO()) == 0
    return db


@pytest.fixture(autouse=True)
def db(real_db, monkeypatch):
    monkeypatch.setenv("REPORT_DB", str(real_db))


@pytest.fixture
def bundle(tmp_path) -> Path:
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(BUNDLE), encoding="utf-8")
    return path


def make_finding(fid, function, params, key_paths, values, data_gap=False):
    return Finding(id=fid, product=params.get("product") or "ALL", statement=f"statement {fid}",
                   values=values, direction="flat", data_gap=data_gap,
                   source={"function": function, "params": params, "key_paths": key_paths})


@pytest.fixture
def findings():
    rows = rt.sector_breakdown(2026, product="EDR")["value"]["rows"]
    summary = rt.product_summary(2026, "EDR")["value"]
    attack_type = next(iter(summary))
    unmapped = rt.unmapped_malware(2026, product="EDR")["value"]["rows"]
    return [
        make_finding("F-001", "sector_breakdown", {"year": 2026, "product": "EDR"},
                     {"v": "value.rows.0.volume"}, {"v": rows[0]["volume"]}),
        make_finding("F-002", "product_summary", {"year": 2026, "product": "EDR"},
                     {"b": f"value.{attack_type}.blocked"}, {"b": summary[attack_type]["blocked"]}),
        make_finding("F-003", "unmapped_malware", {"year": 2026, "product": "EDR"},
                     {"d": "value.rows.0.detections"} if unmapped else {},
                     {"d": unmapped[0]["detections"]} if unmapped else {}, data_gap=True),
    ], rows, summary[attack_type]


# --- labels in the cited data ------------------------------------------------------------------------------

def test_labels_come_from_the_cited_row_only(findings):
    (f1, f2, _), rows, entry = findings
    labels = labels_in_cited_data(f1)
    assert rows[0]["sector"] in labels
    assert rows[1]["sector"] not in labels      # another row of the same result


def test_labels_include_non_zero_keys_only(findings):
    (_, f2, _), _, entry = findings
    labels = labels_in_cited_data(f2)
    for severity, count in entry["by_severity"].items():
        assert (severity in labels) is (count > 0)


@pytest.mark.parametrize("raw, shown, expected", [
    ("Energy", {"Energy"}, ("Energy", "")),
    ("energy", {"Energy"}, ("Energy", "")),                    # standardized case
    ("Multiple", set(), ("multiple", "")),
    ("unspecified", set(), ("unspecified", "")),
    ("Retail", {"Retail"}, ("unspecified", "'Retail' is not a standard value")),
    ("Finance", {"Energy"}, ("unspecified", "'Finance' does not appear in the data the finding cites")),
])
def test_check_sector(raw, shown, expected):
    assert check_label(raw, ingest.SECTORS, {"multiple", "unspecified"}, shown) == expected


def test_multiple_is_not_a_severity():
    assert check_label("multiple", ingest.SEVERITIES, {"unspecified"}, set())[0] == "unspecified"


# --- confidence threshold --------------------------------------------------------------------------------------

def test_confidence_threshold():
    base = {"id": "F-001", "product": "EDR", "statement": "s", "values": {}, "direction": "up",
            "source": {"function": "attacks_blocked", "params": {}, "key_paths": {}}}
    high = NormalizedFinding(**base, confidence=0.9, attack_techniques=[
        {"technique_id": "T1566", "name": "Phishing", "confidence": MIN_CONFIDENCE},
        {"technique_id": "T1190", "name": "Exploit", "confidence": 0.59}])
    low = NormalizedFinding(**{**base, "id": "F-002"}, confidence=0.59)
    kept, review = apply_confidence_threshold([high, low])
    assert [m.technique_id for m in kept[0].attack_techniques] == ["T1566"]
    assert len(kept) == 2   # a low-confidence finding is kept
    assert review == [
        {"finding_id": "F-001", "kind": "technique", "technique_id": "T1190", "name": "Exploit",
         "confidence": 0.59, "rationale": ""},
        {"finding_id": "F-002", "kind": "finding", "confidence": 0.59, "statement": "s"},
    ]


# --- the node --------------------------------------------------------------------------------------------------

def test_normalizer_node(findings, bundle, tmp_path):
    (f1, f2, f3), rows, entry = findings
    severity_shown = next(s for s, c in entry["by_severity"].items() if c > 0)
    severity_absent = next(s for s, c in entry["by_severity"].items() if c == 0)
    llm = FakeChatModel([{"findings": [
        {"finding_id": "F-001", "sector": rows[0]["sector"].lower(), "severity": "high",
         "related_findings": ["F-002", "F-001", "F-099"], "confidence": 0.8,
         "attack_techniques": [{"technique_id": "T1566", "confidence": 0.9},
                               {"technique_id": "T9999", "confidence": 0.9},
                               {"technique_id": "T1001", "confidence": 0.8},
                               {"technique_id": "T1190", "confidence": 0.5}]},
        {"finding_id": "F-002", "sector": "Retail", "severity": severity_shown.upper(),
         "related_findings": ["F-001"], "confidence": 0.5,
         "attack_techniques": [{"technique_id": "t1566.001", "confidence": 0.95},
                               {"technique_id": "T1566.001", "confidence": 0.7}]},
        {"finding_id": "F-777", "confidence": 0.9},
        {"finding_id": "F-001", "confidence": 0.1},
    ]}])
    out = make_normalizer(llm, bundle)({"findings": [f1, f2, f3], "run_dir": str(tmp_path)})
    n1, n2, n3 = out["normalized"]

    # F-001: unknown and revoked IDs rejected, 0.5 mapping left out for review, names added
    assert [(m.technique_id, m.name) for m in n1.attack_techniques] == [("T1566", "Phishing")]
    assert n1.sector == rows[0]["sector"]                        # standardized, and in the cited row
    assert n1.severity == "unspecified"                          # severity not in a sector row
    assert n1.related_findings == ["F-002"]                      # self and unknown removed
    # F-002: duplicate technique kept once, sector reset, severity standardized
    assert [(m.technique_id, m.confidence) for m in n2.attack_techniques] == [("T1566.001", 0.95)]
    assert (n2.sector, n2.severity) == ("unspecified", severity_shown)
    # F-003: the model skipped it
    assert (n3.attack_techniques, n3.confidence) == ([], 0.0)
    # findings are linked, never merged or rewritten
    assert [n.statement for n in out["normalized"]] == [f.statement for f in (f1, f2, f3)]

    review = json.loads((tmp_path / "review.json").read_text())
    assert {(r["finding_id"], r["kind"]) for r in review} == {
        ("F-001", "technique"), ("F-002", "finding"), ("F-003", "finding")}
    assert next(r for r in review if r["kind"] == "technique")["technique_id"] == "T1190"

    corrections = json.loads((tmp_path / "normalizer_corrections.json").read_text())
    reasons = {(c["finding_id"], c["kind"]): c["reason"] for c in corrections}
    assert "does not exist in ATT&CK" in reasons[("F-001", "technique")] or any(
        "does not exist" in c["reason"] for c in corrections)
    assert any("revoked" in c["reason"] for c in corrections)
    assert "does not appear in the data" in reasons[("F-001", "severity")]
    assert "not a standard value" in reasons[("F-002", "sector")]
    assert reasons[("F-777", "normalization")] == "no such finding; ignored"
    assert any(c["reason"] == "duplicate entry; the first one is used" for c in corrections)
    assert "returned no normalization" in reasons[("F-003", "normalization")]
    for name in ("normalizer_output_1.json", "normalized.json"):
        assert (tmp_path / name).exists()


def test_model_sees_findings_and_version(findings, bundle, tmp_path):
    (f1, _, _), _, _ = findings
    llm = FakeChatModel([{"findings": [{"finding_id": "F-001", "confidence": 0.9}]}])
    make_normalizer(llm, bundle)({"findings": [f1], "run_dir": str(tmp_path)})
    system, human = llm.calls[0]
    assert "version 20.1" in system.content and "$" not in system.content
    overview, batch = human.content.split("\n\n", 1)
    assert json.loads(overview.split("\n", 1)[1]) == [
        {"id": "F-001", "product": "EDR", "statement": "statement F-001"}]
    sent = json.loads(batch.split("\n", 1)[1])
    assert sent[0]["id"] == "F-001" and sent[0]["values"] == f1.values
    assert "key_paths" not in json.dumps(sent)


def test_invalid_output_fails_after_one_retry(findings, bundle, tmp_path):
    llm = FakeChatModel(["not json", "still not json"])
    with pytest.raises(StructuredOutputError, match="NormalizerOutput"):
        make_normalizer(llm, bundle)({"findings": findings[0], "run_dir": str(tmp_path)})


def test_no_findings_no_model_call(bundle, tmp_path):
    llm = FakeChatModel([])
    assert make_normalizer(llm, bundle)({"findings": [], "run_dir": str(tmp_path)}) == {"normalized": []}
    assert llm.calls == []
    assert json.loads((tmp_path / "review.json").read_text()) == []


def test_missing_attack_data_fails_before_calling_the_model(findings, tmp_path):
    llm = FakeChatModel([])
    with pytest.raises(AttackDataMissing):
        make_normalizer(llm, tmp_path / "missing.json")({"findings": findings[0], "run_dir": str(tmp_path)})
    assert llm.calls == []


def test_findings_are_sent_in_batches(findings, bundle, tmp_path):
    (f1, f2, f3), _, _ = findings
    llm = FakeChatModel([
        {"findings": [{"finding_id": "F-001", "related_findings": ["F-003"], "confidence": 0.9},
                      {"finding_id": "F-002", "confidence": 0.9}]},   # F-002 belongs to batch 2
        {"findings": [{"finding_id": "F-002", "confidence": 0.7}]},
        {"findings": [{"finding_id": "F-003", "related_findings": ["F-001"], "confidence": 0.8}]},
    ])
    out = make_normalizer(llm, bundle, batch_size=1)({"findings": [f1, f2, f3], "run_dir": str(tmp_path)})
    n1, n2, n3 = out["normalized"]
    assert len(llm.calls) == 3
    assert n1.related_findings == ["F-003"] and n3.related_findings == ["F-001"]   # linked across batches
    assert n2.confidence == 0.7                                                    # from its own batch
    for n in (1, 2, 3):
        assert (tmp_path / f"normalizer_output_{n}.json").exists()
    corrections = json.loads((tmp_path / "normalizer_corrections.json").read_text())
    assert {"finding_id": "F-002", "kind": "normalization", "value": None,
            "reason": "not in this batch; ignored"} in corrections
    # every request lists all findings in short, and only its batch in full
    for call, f in zip(llm.calls, (f1, f2, f3)):
        overview, batch = call[1].content.split("\n\n", 1)
        assert [x["id"] for x in json.loads(overview.split("\n", 1)[1])] == ["F-001", "F-002", "F-003"]
        assert [x["id"] for x in json.loads(batch.split("\n", 1)[1])] == [f.id]


def test_prompt_lists_active_parent_techniques(findings, bundle, tmp_path):
    (f1, _, _), _, _ = findings
    llm = FakeChatModel([{"findings": [{"finding_id": "F-001", "confidence": 0.9}]}])
    make_normalizer(llm, bundle)({"findings": [f1], "run_dir": str(tmp_path)})
    system = llm.calls[0][0].content
    listed = system.split("# ATT&CK techniques", 1)[1]
    assert "T1566 Phishing" in listed and "T1190 Exploit Public-Facing Application" in listed
    assert "T1566.001" not in listed                       # sub-techniques left out
    assert "T1001" not in listed and "T1002" not in listed  # revoked and deprecated left out


def test_normalizer_asks_for_no_reasoning(findings, bundle, tmp_path, monkeypatch):
    import agents.llm
    (f1, _, _), _, _ = findings
    asked = {}
    fake = FakeChatModel([{"findings": [{"finding_id": "F-001", "confidence": 0.9}]}])

    def get_llm(reasoning_effort=None):
        asked["effort"] = reasoning_effort
        return fake

    monkeypatch.setattr(agents.llm, "get_llm", get_llm)
    make_normalizer(None, bundle)({"findings": [f1], "run_dir": str(tmp_path)})
    assert asked["effort"] == "none"
