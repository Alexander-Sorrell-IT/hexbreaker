"""Referential integrity validator for Claim/Verdict citations — Layer 1 in action.

The smoke test (2026-05-26) caught V3 fabricating step_id `S-015` and R1
fabricating `S-102`. Both were prompt-only failures. This validator closes the
loophole in code: a Claim or Verdict is accepted only if every cited step_id
exists in the orchestrator-owned transcript AND the cited stdout_hash matches
what the tool actually emitted.

The validator does NOT call an LLM. It is the deterministic gate around the LLM.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ValidationError

from ..transcript import Kind, StepRecord
from .schema import Claim, StepReference, Verdict

ErrorCode = Literal[
    "schema",
    "missing_step",
    "not_a_tool_call",
    "hash_mismatch",
    "empty_citations",
]


class ValidationIssue(BaseModel):
    code: ErrorCode
    step_id: str | None = None
    detail: str


class ValidationResult(BaseModel):
    ok: bool
    issues: list[ValidationIssue] = []

    @property
    def first_issue(self) -> ValidationIssue | None:
        return self.issues[0] if self.issues else None


def _validate_reference(
    ref: StepReference,
    records_by_id: dict[str, StepRecord],
) -> ValidationIssue | None:
    rec = records_by_id.get(ref.step_id)
    if rec is None:
        return ValidationIssue(
            code="missing_step",
            step_id=ref.step_id,
            detail=f"step_id {ref.step_id} not present in transcript",
        )
    if rec.kind != Kind.TOOL_CALL:
        return ValidationIssue(
            code="not_a_tool_call",
            step_id=ref.step_id,
            detail=f"step_id {ref.step_id} is a {rec.kind.value}, not a tool_call",
        )
    actual_hash = rec.content.get("stdout_hash")
    if actual_hash != ref.stdout_hash:
        return ValidationIssue(
            code="hash_mismatch",
            step_id=ref.step_id,
            detail=f"cited hash for {ref.step_id} does not match the transcript",
        )
    return None


def _check_citations(
    cited_steps: list[StepReference],
    records_by_id: dict[str, StepRecord],
) -> list[ValidationIssue]:
    if not cited_steps:
        return [ValidationIssue(code="empty_citations", detail="no cited_steps")]
    issues: list[ValidationIssue] = []
    for ref in cited_steps:
        issue = _validate_reference(ref, records_by_id)
        if issue is not None:
            issues.append(issue)
    return issues


def _records_by_id(records: list[StepRecord]) -> dict[str, StepRecord]:
    return {r.step_id: r for r in records}


def validate_claim_json(
    raw_json: str | bytes,
    transcript_records: list[StepRecord],
) -> tuple[ValidationResult, Claim | None]:
    """Parse + validate a Claim emitted by the Prosecutor."""
    try:
        claim = Claim.model_validate_json(raw_json)
    except ValidationError as e:
        return ValidationResult(
            ok=False,
            issues=[ValidationIssue(code="schema", detail=str(e))],
        ), None

    issues = _check_citations(claim.cited_steps, _records_by_id(transcript_records))
    return ValidationResult(ok=not issues, issues=issues), (claim if not issues else None)


def validate_verdict_json(
    raw_json: str | bytes,
    transcript_records: list[StepRecord],
) -> tuple[ValidationResult, Verdict | None]:
    """Parse + validate a Verdict emitted by the Defender."""
    try:
        verdict = Verdict.model_validate_json(raw_json)
    except ValidationError as e:
        return ValidationResult(
            ok=False,
            issues=[ValidationIssue(code="schema", detail=str(e))],
        ), None

    issues = _check_citations(verdict.cited_steps, _records_by_id(transcript_records))
    return ValidationResult(ok=not issues, issues=issues), (verdict if not issues else None)
