"""Tests for the ATT&CK lookup (agents/attack.py) and scripts/fetch_attack.py.

A small hand-written STIX bundle is used; one test also checks the real
downloaded bundle and is skipped if it is not there.
"""

import hashlib
import importlib.util
import io
import json
from pathlib import Path

import pytest

from agents.attack import BUNDLE_PATH, AttackDataMissing, check_technique, load_techniques, technique_name

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fetch_attack", ROOT / "scripts" / "fetch_attack.py")
fetch_attack = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fetch_attack)


def technique(tid, name, **extra):
    return {"type": "attack-pattern", "id": f"attack-pattern--{tid}", "name": name,
            "external_references": [{"source_name": "mitre-attack", "external_id": tid}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
            **extra}


BUNDLE = {"type": "bundle", "id": "bundle--test", "objects": [
    technique("T1566", "Phishing"),
    technique("T1566.001", "Spearphishing Attachment", x_mitre_is_subtechnique=True),
    technique("T1190", "Exploit Public-Facing Application"),
    technique("T1001", "Old Technique", revoked=True),
    technique("T1002", "Retired Technique", x_mitre_deprecated=True),
    {"type": "attack-pattern", "id": "attack-pattern--x", "name": "No MITRE ID",
     "external_references": [{"source_name": "capec", "external_id": "CAPEC-1"}]},
    {"type": "intrusion-set", "id": "intrusion-set--x", "name": "Some Group",
     "external_references": [{"source_name": "mitre-attack", "external_id": "G0001"}]},
]}


@pytest.fixture
def bundle(tmp_path) -> Path:
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(BUNDLE), encoding="utf-8")
    return path


# --- lookup ------------------------------------------------------------------------------------------

def test_loads_only_techniques_with_mitre_ids(bundle):
    assert set(load_techniques(bundle)) == {"T1566", "T1566.001", "T1190", "T1001", "T1002"}
    assert load_techniques(bundle)["T1566"].tactics == ("initial-access",)


@pytest.mark.parametrize("tid, name", [
    ("T1566", "Phishing"),
    ("T1566.001", "Spearphishing Attachment"),
    (" t1190 ", "Exploit Public-Facing Application"),   # case and spaces are tolerated
])
def test_valid_techniques(bundle, tid, name):
    assert check_technique(tid, bundle) == (name, "")
    assert technique_name(tid, bundle) == name


@pytest.mark.parametrize("tid, reason", [
    ("T9999", "does not exist in ATT&CK"),
    ("T1566.999", "does not exist in ATT&CK"),
    ("T1001", "is revoked"),
    ("T1002", "is deprecated"),
    ("G0001", "not a technique ID"),
    ("1566", "not a technique ID"),
    ("T1566.1", "not a technique ID"),
    ("", "not a technique ID"),
])
def test_rejected_techniques(bundle, tid, reason):
    name, problem = check_technique(tid, bundle)
    assert name is None and reason in problem
    assert technique_name(tid, bundle) is None


def test_missing_bundle_says_how_to_fix(tmp_path):
    with pytest.raises(AttackDataMissing, match="python scripts/fetch_attack.py"):
        load_techniques(tmp_path / "missing.json")


@pytest.mark.skipif(not BUNDLE_PATH.exists(), reason="ATT&CK bundle not downloaded")
def test_real_bundle():
    techniques = load_techniques()
    active = [t for t in techniques.values() if not t.revoked and not t.deprecated]
    assert len(active) > 500
    assert technique_name("T1566") == "Phishing"
    assert technique_name("T1059.001") == "PowerShell"


# --- fetch script --------------------------------------------------------------------------------------

def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_fetch(source: Path, dest: Path, expected, *args):
    out = io.StringIO()
    code = fetch_attack.main(list(args), url=source.as_uri(), dest=dest, expected_sha256=expected, out=out)
    return code, out.getvalue()


def test_fetch_downloads_and_checks_the_hash(bundle, tmp_path):
    dest = tmp_path / "out" / "attack.json"
    code, out = run_fetch(bundle, dest, sha(bundle))
    assert code == 0 and "SAVED" in out
    assert dest.read_bytes() == bundle.read_bytes()


def test_fetch_rejects_a_wrong_hash_and_leaves_nothing(bundle, tmp_path):
    dest = tmp_path / "out" / "attack.json"
    code, out = run_fetch(bundle, dest, "0" * 64)
    assert code == 1 and "SHA-256 mismatch" in out
    assert list(dest.parent.iterdir()) == []   # no file, no leftover .part file


def test_fetch_rejects_a_file_that_is_not_a_bundle(tmp_path):
    source = tmp_path / "not_bundle.json"
    source.write_text('{"type": "something"}', encoding="utf-8")
    code, out = run_fetch(source, tmp_path / "out" / "a.json", None)
    assert code == 1 and "not a STIX bundle" in out


def test_fetch_skips_a_good_existing_file(bundle, tmp_path):
    dest = tmp_path / "installed.json"
    dest.write_bytes(bundle.read_bytes())
    code, out = run_fetch(tmp_path / "does_not_exist.json", dest, sha(bundle))
    assert code == 0 and "already present" in out


def test_fetch_replaces_a_corrupt_existing_file(bundle, tmp_path):
    dest = tmp_path / "installed.json"
    dest.write_text("corrupt", encoding="utf-8")
    code, out = run_fetch(bundle, dest, sha(bundle))
    assert code == 0 and "not usable" in out and "SAVED" in out
    assert sha(dest) == sha(bundle)


def test_fetch_force_downloads_again(bundle, tmp_path):
    dest = tmp_path / "installed.json"
    dest.write_bytes(bundle.read_bytes())
    code, out = run_fetch(bundle, dest, sha(bundle), "--force")
    assert code == 0 and "SAVED" in out


def test_pinned_version_and_hash():
    assert fetch_attack.ATTACK_VERSION == "20.1"
    assert len(fetch_attack.EXPECTED_SHA256) == 64
    assert fetch_attack.ATTACK_VERSION in fetch_attack.URL
