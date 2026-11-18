"""MITRE ATT&CK technique lookup (SPEC 7.2), from the bundle that
scripts/fetch_attack.py downloads. No network access.

    technique_name("T1566")      -> "Phishing"   (or the name in the pinned version)
    technique_name("T9999")      -> None
    check_technique("T1001")     -> (None, "revoked in ATT&CK ...")

Revoked and deprecated techniques are in the dataset but must not be used,
so they count as invalid.
"""

import importlib.util
import json
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# The pinned version and file location are defined once, in the download script.
_spec = importlib.util.spec_from_file_location("fetch_attack", PROJECT_ROOT / "scripts" / "fetch_attack.py")
_fetch = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fetch)
ATTACK_VERSION: str = _fetch.ATTACK_VERSION
BUNDLE_PATH: Path = _fetch.DEST
TECHNIQUE_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


class AttackDataMissing(RuntimeError):
    """The ATT&CK bundle has not been downloaded."""


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    revoked: bool
    deprecated: bool


@lru_cache(maxsize=4)
def load_techniques(path: Path = BUNDLE_PATH) -> dict[str, Technique]:
    """All techniques and sub-techniques in the bundle, by ID (e.g. 'T1566.001')."""
    path = Path(path)
    if not path.is_file():
        raise AttackDataMissing(
            f"MITRE ATT&CK data not found at {path}. Run `python scripts/fetch_attack.py` first.")
    bundle = json.loads(path.read_text(encoding="utf-8"))
    techniques = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tid = next((r.get("external_id") for r in obj.get("external_references", [])
                    if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        techniques[tid] = Technique(
            id=tid,
            name=obj.get("name", ""),
            tactics=tuple(p["phase_name"] for p in obj.get("kill_chain_phases", [])
                          if p.get("kill_chain_name") == "mitre-attack"),
            revoked=bool(obj.get("revoked")),
            deprecated=bool(obj.get("x_mitre_deprecated")),
        )
    return techniques


def check_technique(technique_id: str, path: Path = BUNDLE_PATH) -> tuple[str | None, str]:
    """Return (name, "") for a valid technique, or (None, reason) if it must be rejected."""
    tid = technique_id.strip().upper()
    if not TECHNIQUE_ID_RE.fullmatch(tid):
        return None, f"{technique_id!r} is not a technique ID (expected T1234 or T1234.001)"
    technique = load_techniques(path).get(tid)
    if technique is None:
        return None, f"{tid} does not exist in ATT&CK {ATTACK_VERSION}"
    if technique.revoked:
        return None, f"{tid} ({technique.name}) is revoked in ATT&CK {ATTACK_VERSION}"
    if technique.deprecated:
        return None, f"{tid} ({technique.name}) is deprecated in ATT&CK {ATTACK_VERSION}"
    return technique.name, ""


def technique_name(technique_id: str, path: Path = BUNDLE_PATH) -> str | None:
    """The technique's name if the ID exists and is in use; otherwise None."""
    return check_technique(technique_id, path)[0]
