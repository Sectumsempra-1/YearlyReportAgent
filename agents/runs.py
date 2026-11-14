"""Run folders: runs/<run_id>/ holds every node's output (SPEC section 10)."""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RUNS_ROOT = PROJECT_ROOT / "runs"


def create_run_dir(root: Path = RUNS_ROOT) -> tuple[str, Path]:
    """New run ID (UTC timestamp) and its folder. A suffix keeps IDs unique."""
    base = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_id, n = base, 1
    while (root / run_id).exists():
        n += 1
        run_id = f"{base}-{n}"
    path = root / run_id
    path.mkdir(parents=True)
    return run_id, path


def _plain(obj):
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, dict):
        return {k: _plain(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_plain(v) for v in obj]
    return obj


def save(run_dir: str | Path, name: str, data) -> Path:
    """Write data (Pydantic models, dicts, lists) as JSON to runs/<run_id>/<name>."""
    path = Path(run_dir) / name
    path.write_text(json.dumps(_plain(data), indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def save_text(run_dir: str | Path, name: str, text: str) -> Path:
    path = Path(run_dir) / name
    path.write_text(text, encoding="utf-8")
    return path


def append(run_dir: str | Path, name: str, item) -> Path:
    """Append an item to a JSON list file (e.g. approvals.json)."""
    path = Path(run_dir) / name
    items = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    items.append(_plain(item))
    return save(run_dir, name, items)


def next_version(run_dir: str | Path, stem: str) -> int:
    """1 + the number of <stem>_<n>.json files already in the run folder."""
    return len(list(Path(run_dir).glob(f"{stem}_*.json"))) + 1


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", text.lower()).strip("_")
