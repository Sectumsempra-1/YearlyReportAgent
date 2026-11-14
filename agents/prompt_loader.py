"""Load system prompts from agents/prompts/*.md and fill in $placeholders."""

from pathlib import Path
from string import Template

PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"


def load_prompt(name: str, **values) -> str:
    """Read prompts/<name>.md and substitute $name placeholders. All must be filled."""
    text = (PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8")
    return Template(text).substitute(**{k: str(v) for k, v in values.items()})
