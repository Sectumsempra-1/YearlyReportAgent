"""Data contracts (docs/SPEC.md section 8) and the graph state that holds them.

Every piece of data passed between nodes is one of these Pydantic models.
LLM output is validated against them; code-only fields (finding IDs,
direction, caveats) are set by code, never by the model (SPEC 7.1b).
"""

import operator
import re
from typing import Annotated, Any, Literal, Optional, TypedDict

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

import report_tools
from ingest import SECTORS, SEVERITIES

FINDING_ID = r"^F-\d{3,}$"
TECHNIQUE_ID = r"^T\d{4}(\.\d{3})?$"
NUMBER_TEXT = re.compile(r"-?\d+(\.\d+)?")   # a plain number written as text, e.g. "1.5"

FunctionName = Literal[tuple(f.__name__ for f in report_tools.TOOLS)]  # type: ignore[valid-type]
Direction = Literal["up", "down", "flat", "new"]
SectorValue = Literal[tuple(sorted(SECTORS)) + ("multiple", "unspecified")]  # type: ignore[valid-type]
SeverityValue = Literal[tuple(sorted(SEVERITIES)) + ("unspecified",)]  # type: ignore[valid-type]
Value = int | float | str | bool | None

# Report sections in order (SPEC section 1). Section writers produce the five
# in OUTLINE_SECTIONS; the executive summary and methodology are separate.
EXEC_SUMMARY_ID = "executive_summary"
METHODOLOGY_ID = "methodology"
SECTION_TITLES = {
    EXEC_SUMMARY_ID: "Executive summary",
    "product_performance": "Product performance",
    "top_malware": "Top malware",
    "source_countries": "Source countries",
    "trends": "Trends",
    "recommendations": "Recommendations",
    METHODOLOGY_ID: "Methodology and data gaps",
}
OUTLINE_SECTIONS = ("product_performance", "top_malware", "source_countries", "trends", "recommendations")
REPORT_ORDER = tuple(SECTION_TITLES)
MAX_ATTEMPTS = 4  # per section: first write + up to 3 rewrites (SPEC 7.5)


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --- findings ------------------------------------------------------------------------------

class Source(Model):
    """The tool call a finding came from, and where each value sits in its result."""
    function: FunctionName
    params: dict[str, Any]
    key_paths: dict[str, str] = Field(
        description="value name -> dotted path into the tool result, e.g. 'value.rows.0.share_pct'")


class FindingOutput(Model):
    """One finding as the analyst model writes it (no product, id or direction)."""
    statement: str = Field(min_length=1)
    values: dict[str, Value] = Field(description="Values copied from the tool result")
    source: Source
    caveats: list[str] = Field(default=[], description="The cited result's caveats, copied")
    data_gap: bool = False

    @field_validator("values")
    @classmethod
    def _numbers_written_as_text(cls, values):
        """A number the model wrote as text ("1.5") is the number 1.5. Other text stays text."""
        out = {}
        for key, value in values.items():
            if isinstance(value, str) and NUMBER_TEXT.fullmatch(value.strip()):
                text = value.strip()
                value = float(text) if "." in text else int(text)
            out[key] = value
        return out

    @model_validator(mode="after")
    def _values_match_key_paths(self):
        extra = set(self.source.key_paths) - set(self.values)
        if extra and set(self.values) <= set(self.source.key_paths):
            # A path for a value the finding does not use (e.g. a rank) is harmless: drop it.
            self.source = self.source.model_copy(
                update={"key_paths": {k: v for k, v in self.source.key_paths.items() if k in self.values}})
        if set(self.values) != set(self.source.key_paths):
            raise ValueError(
                f"values and source.key_paths must have the same keys: "
                f"{sorted(self.values)} vs {sorted(self.source.key_paths)}")
        return self


class AnalystOutput(Model):
    """The analyst model's final answer. Each finding is checked on its own
    (FindingOutput), so one broken finding does not cost the others."""
    findings: list[dict[str, Any]]


class FindingDraft(FindingOutput):
    """An analyst finding after code has set the product. Code turns it into a Finding."""
    product: str = Field(description="Product name, or 'ALL' for cross-product findings")


class Finding(FindingDraft):
    """A draft plus the fields set by code: id and direction. Code also replaces
    caveats with the cited result's exact caveats."""
    id: str = Field(pattern=FINDING_ID)
    direction: Direction


class TechniqueMapping(Model):
    technique_id: str = Field(pattern=TECHNIQUE_ID)
    name: str = Field(default="", description="Set by code from the ATT&CK dataset")
    confidence: float = Field(ge=0, le=1)
    rationale: str = ""


class NormalizedFinding(Finding):
    attack_techniques: list[TechniqueMapping] = []
    sector: SectorValue = "unspecified"
    severity: SeverityValue = "unspecified"
    related_findings: list[str] = []
    confidence: float = Field(ge=0, le=1)

    @field_validator("related_findings")
    @classmethod
    def _related_are_ids(cls, ids):
        bad = [i for i in ids if not re.match(FINDING_ID, i)]
        if bad:
            raise ValueError(f"not finding IDs: {bad}")
        return ids


class TechniqueOutput(Model):
    """A technique mapping as the normalizer model writes it; code validates the ID."""
    technique_id: str
    confidence: float = Field(ge=0, le=1)
    rationale: str = Field(default="", description="What in the finding points to this technique")


class FindingNormalization(Model):
    """The normalizer model's answer for one finding. Strings are checked by code,
    so one bad value is corrected and logged instead of failing the whole answer."""
    finding_id: str
    attack_techniques: list[TechniqueOutput] = []
    sector: str = "unspecified"
    severity: str = "unspecified"
    related_findings: list[str] = []
    confidence: float = Field(ge=0, le=1)


class NormalizerOutput(Model):
    findings: list[FindingNormalization]


# --- outline, sections, verification -----------------------------------------------------------

class SignatureMetric(Model):
    finding_id: str = Field(pattern=FINDING_ID)
    value_key: str


class Theme(Model):
    title: str = Field(min_length=1)
    summary: str = Field(min_length=1)
    finding_ids: list[str] = Field(min_length=1)


class OutlineSection(Model):
    id: Literal[OUTLINE_SECTIONS]  # type: ignore[valid-type]
    title: str = Field(min_length=1)
    goal: str = Field(min_length=1)
    finding_ids: list[str] = Field(min_length=1)


class Outline(Model):
    thesis: str = Field(min_length=1)
    signature_metric: SignatureMetric
    themes: list[Theme] = Field(min_length=3, max_length=5, description="Ranked by importance")
    sections: list[OutlineSection]

    @model_validator(mode="after")
    def _all_sections_once(self):
        ids = [s.id for s in self.sections]
        if sorted(ids) != sorted(OUTLINE_SECTIONS):
            raise ValueError(f"sections must be exactly {list(OUTLINE_SECTIONS)} once each, got {ids}")
        return self

    def finding_ids(self) -> set[str]:
        ids = {self.signature_metric.finding_id}
        for group in (*self.themes, *self.sections):
            ids.update(group.finding_ids)
        return ids


class Section(Model):
    id: str
    title: str
    markdown: str
    finding_ids_used: list[str] = []


class VerificationError(Model):
    sentence: str
    problem: str
    expected: Optional[str] = None


class VerificationResult(Model):
    section_id: str
    passed: bool
    errors: list[VerificationError] = []

    @model_validator(mode="after")
    def _passed_means_no_errors(self):
        if self.passed == bool(self.errors):
            raise ValueError("passed must be true exactly when there are no errors")
        return self


class Approval(Model):
    step: Literal["outline", "report"]
    decision: Literal["approve", "reject", "abort"]
    comment: str = ""


# --- graph state ----------------------------------------------------------------------------------

def merge(left: dict | None, right: dict | None) -> dict:
    """Reducer for dicts written by parallel nodes: later keys win."""
    return {**(left or {}), **(right or {})}


class ReportState(TypedDict, total=False):
    # set at start
    year: int
    run_id: str
    run_dir: str
    # analysis
    products: list[str]
    drafts: Annotated[list[FindingDraft], operator.add]   # appended by parallel analysts
    findings: list[Finding]
    normalized: list[NormalizedFinding]
    outline: Outline
    outline_feedback: str
    # writing
    sections: Annotated[dict[str, Section], merge]         # section id -> verified section
    attempts: Annotated[dict[str, int], merge]             # section id -> attempts used
    failed: Annotated[dict[str, list[VerificationError]], merge]  # section id -> last errors
    conflicts: dict[str, list[VerificationError]]          # sections to rewrite for consistency
    report_feedback: str
    # control
    approvals: Annotated[list[Approval], operator.add]
    status: Literal["running", "completed", "failed", "aborted"]


class LoopState(TypedDict, total=False):
    """State of one write -> verify -> retry loop (one section, or the executive summary)."""
    year: int
    run_dir: str
    section_id: str
    title: str
    goal: str
    findings: list[NormalizedFinding]        # only the findings assigned to this section
    outline: Outline
    verified_sections: dict[str, Section]    # executive summary only
    feedback: str                            # human comment on a rejected report
    round: int                               # 1, or 1 + number of report rejections
    attempt: int
    draft: Section
    verification: VerificationResult
