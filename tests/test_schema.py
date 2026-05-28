"""Tests for Claim/Verdict/StepReference Pydantic schemas — Layer 3."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hexbreaker.court.schema import Claim, StepReference, Verdict

VALID_HASH = "sha256:" + "a" * 64


def test_step_reference_accepts_valid() -> None:
    s = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    assert s.step_id == "S-001"


def test_step_reference_rejects_bad_step_id() -> None:
    with pytest.raises(ValidationError):
        StepReference(step_id="bogus-7", stdout_hash=VALID_HASH)


def test_step_reference_rejects_bad_hash() -> None:
    with pytest.raises(ValidationError):
        StepReference(step_id="S-001", stdout_hash="md5:1234")


def test_verdict_requires_non_empty_citations() -> None:
    with pytest.raises(ValidationError):
        Verdict(
            verdict="CONFIRMED",
            cited_steps=[],
            challenge_text="empty",
        )


def test_verdict_rejects_duplicate_citations() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    with pytest.raises(ValidationError):
        Verdict(
            verdict="CONFIRMED",
            cited_steps=[ref, ref],
            challenge_text="dup",
        )


def test_verdict_confidence_range() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    Verdict(verdict="CONTESTED", cited_steps=[ref], challenge_text="ok", confidence=0.5)
    with pytest.raises(ValidationError):
        Verdict(verdict="CONTESTED", cited_steps=[ref], challenge_text="ok", confidence=1.5)


def test_verdict_rejects_unknown_kind() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    with pytest.raises(ValidationError):
        Verdict(
            verdict="MAYBE",  # type: ignore[arg-type]
            cited_steps=[ref],
            challenge_text="x",
        )


def test_claim_requires_artifact_kind() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    Claim(text="found evil", artifact_kind="timestomp", target="suspicious.sys", cited_steps=[ref])
    with pytest.raises(ValidationError):
        Claim(text="x", artifact_kind="invalid", target="suspicious.sys", cited_steps=[ref])  # type: ignore[arg-type]


def test_claim_rejects_empty_text() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    with pytest.raises(ValidationError):
        Claim(text="", artifact_kind="timestomp", target="x", cited_steps=[ref])


def test_claim_requires_target() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    with pytest.raises(ValidationError):
        Claim(text="hi", artifact_kind="timestomp", target="", cited_steps=[ref])


def test_verdict_extras_rejected() -> None:
    ref = StepReference(step_id="S-001", stdout_hash=VALID_HASH)
    with pytest.raises(ValidationError):
        Verdict.model_validate(
            {
                "verdict": "CONFIRMED",
                "cited_steps": [ref.model_dump()],
                "challenge_text": "x",
                "unexpected": "field",
            }
        )
