"""Download MITRE's Enterprise ATT&CK STIX bundle (setup step, not part of a run).

Usage:
    python scripts/fetch_attack.py           # download if missing or corrupt
    python scripts/fetch_attack.py --force   # download again

Source: the mitre-attack/attack-stix-data GitHub repository. The version is
pinned (ATTACK_VERSION) and the file is checked against a pinned SHA-256, so
every run maps techniques against the same dataset. The pipeline never
downloads anything itself (rule 7); it fails with a clear error if the file
is missing.

Saved to data/reference/attack/enterprise-attack-<version>.json (gitignored).
Exit code: 0 ok, 1 download or check failed.
"""

import argparse
import hashlib
import json
import os
import sys
import tempfile
import urllib.request
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ATTACK_VERSION = "20.1"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
       f"enterprise-attack/enterprise-attack-{ATTACK_VERSION}.json")
EXPECTED_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"
DEST_DIR = PROJECT_ROOT / "data" / "reference" / "attack"
DEST = DEST_DIR / f"enterprise-attack-{ATTACK_VERSION}.json"


class FetchError(RuntimeError):
    pass


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_bundle(path: Path, expected_sha256: str | None) -> str:
    """Check the file's hash (if pinned) and that it is a STIX bundle with techniques."""
    digest = sha256_of(path)
    if expected_sha256 and digest != expected_sha256:
        raise FetchError(f"SHA-256 mismatch: expected {expected_sha256}, got {digest}")
    try:
        bundle = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FetchError(f"not valid JSON: {exc}") from exc
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise FetchError("not a STIX bundle")
    if not any(o.get("type") == "attack-pattern" for o in bundle.get("objects", [])):
        raise FetchError("bundle contains no techniques (attack-pattern objects)")
    return digest


def download(url: str, dest: Path, expected_sha256: str | None, timeout: int = 120) -> str:
    """Download to a temporary file, check it, then move it into place."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, suffix=".part")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as out, urllib.request.urlopen(url, timeout=timeout) as response:
            while chunk := response.read(1 << 20):
                out.write(chunk)
        digest = check_bundle(tmp, expected_sha256)
        tmp.replace(dest)
        return digest
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def main(argv=None, url: str = URL, dest: Path = DEST, expected_sha256: str | None = EXPECTED_SHA256,
         out=sys.stdout) -> int:
    parser = argparse.ArgumentParser(description="Download the Enterprise ATT&CK STIX bundle.")
    parser.add_argument("--force", action="store_true", help="download even if the file is present")
    args = parser.parse_args(argv)

    if dest.exists() and not args.force:
        try:
            digest = check_bundle(dest, expected_sha256)
            print(f"OK       {dest} already present (ATT&CK {ATTACK_VERSION}, sha256 {digest})", file=out)
            return 0
        except FetchError as exc:
            print(f"Existing file is not usable ({exc}); downloading again.", file=out)

    print(f"Downloading ATT&CK {ATTACK_VERSION} from {url}", file=out)
    try:
        digest = download(url, dest, expected_sha256)
    except Exception as exc:
        print(f"FAILED   {type(exc).__name__}: {exc}", file=out)
        return 1
    print(f"SAVED    {dest} (sha256 {digest})", file=out)
    if not expected_sha256:
        print("WARNING  no pinned SHA-256; set EXPECTED_SHA256 in this script to the value above.", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
